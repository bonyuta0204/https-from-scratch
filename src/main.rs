mod http;

use http::http2::Http2Client;
use http::{HttpClient, Request};

fn main() -> std::io::Result<()> {
    let result = Http2Client::new().request(Request::new(
        "https://example.com".to_string(),
        "GET".to_string(),
        vec![],
        None,
    ));
    Ok(())
}
