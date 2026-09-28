//! Public same-origin resources: `/assets/*`、`/cdn/*`（固定 CDN 上游）与
//! `/internal-upstream/https/<host>/...`（注入脚本内置主机表的媒体代理）。
//! 两者都不转发账号凭据，并拒绝重定向与 text/html。
//! Route mapping observed in phase1/page-original-001; credential stripping is
//! intentionally stricter than the original gateway's Authorization forwarding.
use super::*;
use axum::http::Method;
use futures_util::TryStreamExt;

/// 页面同源需要的一级静态类型。原版把 `/assets/*`、`/cdn/*` 直接反代 CDN，
/// 因此这里按扩展名放行脚本、样式、图片、字体与音视频，其余一律 503。
const ASSET_EXTENSIONS: [&str; 21] = [
    "js", "css", "mjs", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp", "woff",
    "woff2", "ttf", "otf", "eot", "mp3", "mp4", "webm", "ogg",
];

fn asset_extension(path: &str) -> Option<&str> {
    path.rsplit_once('.').map(|(_, extension)| extension)
}

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
    {
        return None;
    }
    let extension = asset_extension(target)?;
    if !ASSET_EXTENSIONS
        .iter()
        .any(|allowed| extension.eq_ignore_ascii_case(allowed))
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
    // 复制路径，避免把 request 的借用带进下面按类型判定的闭包。
    let Some(path) = asset_path(request.uri().path()).map(str::to_owned) else {
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
    target.set_path(&path);
    target.set_query(request.uri().query());
    forward_public(app, request, target, |content_type| {
        if path.ends_with(".css") {
            content_type.eq_ignore_ascii_case("text/css")
        } else if path.ends_with(".js") || path.ends_with(".mjs") {
            content_type.eq_ignore_ascii_case("application/javascript")
                || content_type.eq_ignore_ascii_case("text/javascript")
        } else {
            // 媒体只要求不是 HTML：同源下的 text/html 会变成可执行页面。
            !content_type.eq_ignore_ascii_case("text/html")
        }
    })
    .await
}

/// 内部上游媒体代理允许的方法（方法门禁在 `proxy::chat_proxy` 统一判定）。
pub(super) const MEDIA_ALLOW: &str = "GET, HEAD, PUT";

/// 白名单内部上游主机的媒体代理入口：不携带账号凭据，正文按方法透传
/// （`PUT` 用于匿名上传返回的签名 blob 地址）。
pub(super) async fn media(app: &App, request: Request, target: url::Url) -> Response {
    forward_public(app, request, target, |content_type| {
        !content_type.eq_ignore_ascii_case("text/html")
    })
    .await
}

/// 公共资源反代：请求头白名单 + 完整身份组，拒绝重定向、非 2xx 与 HTML 正文，
/// 响应只复制安全头并流式回传。凭据一律不转发。
pub(super) async fn forward_public<F>(
    app: &App,
    request: Request,
    target: url::Url,
    accepted: F,
) -> Response
where
    F: Fn(&str) -> bool,
{
    let (parts, body) = request.into_parts();
    let mut headers = HeaderMap::new();
    // Public CDN requests never receive browser, gateway, account or CF credentials.
    for name in [
        "accept",
        "accept-encoding",
        "accept-language",
        "if-none-match",
        "if-modified-since",
        "range",
        "if-range",
        "content-type",
        "x-ms-blob-type",
    ] {
        if let Some(value) = parts.headers.get(name) {
            headers.insert(name, value.clone());
        }
    }
    identity::apply_identity(&mut headers);
    let upstream = app
        .client
        .request(parts.method.clone(), target.as_str())
        .headers(headers);
    // 读取类请求无正文；签名上传（PUT）按流透传，避免把文件整体缓存在网关内存里。
    if matches!(parts.method, Method::PUT) {
        let request = upstream.body(wreq::Body::wrap_stream(body.into_data_stream()));
        return send_public_request(request, accepted).await;
    }
    send_public_request(upstream, accepted).await
}

async fn send_public_request<F>(
    upstream: wreq::RequestBuilder,
    accepted: F,
) -> Response
where
    F: Fn(&str) -> bool,
{
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
        if !accepted(content_type) {
            return error(StatusCode::BAD_GATEWAY, "静态资源上游类型不匹配").into_response();
        }
    }
    stream_public_response(upstream)
}

/// 公共资源的成功响应组装：只复制安全头（不含 `set-cookie`），正文流式回传。
pub(super) fn stream_public_response(upstream: wreq::Response) -> Response {
    let status = upstream.status();
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
            "/assets/page.html",
            "/assets/no-extension",
            "/cdn/backend-api/me.js",
            "/cdn//host/a.js",
            "/backend-api/me",
        ] {
            assert_eq!(asset_path(path), None, "{path}");
        }
    }

    /// 页面渲染需要的图片/字体/音视频与大小写扩展名同样属于公共静态资源。
    #[test]
    fn media_extensions_are_public_assets() {
        assert_eq!(asset_path("/assets/logo.png"), Some("/assets/logo.png"));
        assert_eq!(
            asset_path("/assets/font-1.WOFF2"),
            Some("/assets/font-1.WOFF2")
        );
        assert_eq!(
            asset_path("/assets/avatar.webp"),
            Some("/assets/avatar.webp")
        );
        assert_eq!(asset_path("/assets/icon.svg"), Some("/assets/icon.svg"));
        assert_eq!(asset_path("/cdn/avatar-1.jpg"), Some("/avatar-1.jpg"));
    }
}
