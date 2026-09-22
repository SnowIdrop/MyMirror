//! Public JS/CSS only. Media and unknown paths remain behind the business gate.
//! Route mapping observed in phase1/page-original-001; credential stripping is
//! intentionally stricter than the original gateway's Authorization forwarding.
use super::*;
use axum::http::Method;
use futures_util::TryStreamExt;

fn asset_path(path: &str) -> Option<&str> {
    let target = if path.starts_with("/assets/") {
        path
    } else {
        let target = path.strip_prefix("/cdn/")?;
        if !target.starts_with("assets/") && target.contains('/') {
            return None;
        }
        &path[4..]
    };
    if !target
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c))
        || target[1..]
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
        || !(target.ends_with(".js") || target.ends_with(".css"))
    {
        return None;
    }
    Some(target)
}

pub(super) async fn serve(app: &App, request: Request) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        let mut response =
            error(StatusCode::METHOD_NOT_ALLOWED, "静态资源仅支持 GET/HEAD").into_response();
        response
            .headers_mut()
            .insert("allow", HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let Some(path) = asset_path(request.uri().path()) else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "静态资源路径尚未通过兼容门禁",
        )
        .into_response();
    };
    let Some(mut target) = app.config.cdn_upstream.clone() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CHATGPT_CDN_BASE_URL 未配置",
        )
        .into_response();
    };
    target.set_path(path);
    target.set_query(request.uri().query());
    let mut upstream = app
        .client
        .request(request.method().clone(), target)
        .header("user-agent", proxy::DEFAULT_USER_AGENT);
    // Public CDN requests never receive browser, gateway, account or CF credentials.
    for name in [
        "accept",
        "accept-encoding",
        "accept-language",
        "if-none-match",
        "if-modified-since",
        "range",
        "if-range",
    ] {
        if let Some(value) = request.headers().get(name) {
            upstream = upstream.header(name, value);
        }
    }
    let upstream = match upstream.send().await {
        Ok(value) => value,
        Err(cause) => {
            tracing::warn!(error=%cause, "public static upstream failed");
            return error(StatusCode::BAD_GATEWAY, "静态资源上游不可用").into_response();
        }
    };
    let status = upstream.status();
    if status != StatusCode::NOT_MODIFIED {
        if status.is_redirection() {
            return error(StatusCode::BAD_GATEWAY, "静态资源上游重定向未开放").into_response();
        }
        if !status.is_success() {
            return error(status, "静态资源上游请求失败").into_response();
        }
        let content_type = upstream
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let expected = if path.ends_with(".css") {
            content_type.eq_ignore_ascii_case("text/css")
        } else {
            content_type.eq_ignore_ascii_case("application/javascript")
                || content_type.eq_ignore_ascii_case("text/javascript")
        };
        if !expected {
            return error(StatusCode::BAD_GATEWAY, "静态资源上游类型不匹配").into_response();
        }
    }
    let mut headers = HeaderMap::new();
    for name in [
        "content-type",
        "content-encoding",
        "content-language",
        "etag",
        "last-modified",
        "accept-ranges",
        "content-range",
        "vary",
    ] {
        for value in upstream.headers().get_all(name) {
            headers.append(name, value.clone());
        }
    }
    let mut response = Response::new(Body::from_stream(
        upstream.bytes_stream().map_err(std::io::Error::other),
    ));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response.extensions_mut().insert(ProxiedResponse);
    response
}

#[cfg(test)]
mod tests {
    use super::asset_path;

    #[test]
    fn maps_observed_public_routes_only() {
        assert_eq!(asset_path("/assets/fixture.js"), Some("/assets/fixture.js"));
        assert_eq!(asset_path("/cdn/fixture.css"), Some("/fixture.css"));
        assert_eq!(
            asset_path("/cdn/assets/chunk-1.js"),
            Some("/assets/chunk-1.js")
        );
        for path in [
            "/cdn",
            "/cdn/",
            "/cdn/../secret.js",
            "/assets/%2e%2e/secret.js",
            "/assets/a%2fsecret.js",
            "/assets/a\\secret.js",
            "/assets//a.js",
            "/assets/a.json",
            "/assets/private.png",
            "/cdn/backend-api/me.js",
            "/cdn//host/a.js",
            "/backend-api/me",
        ] {
            assert_eq!(asset_path(path), None, "{path}");
        }
    }
}
