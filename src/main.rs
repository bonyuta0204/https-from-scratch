mod http;

use http::http2::Http2Client;
use http::{Error, HttpClient, Request};

fn main() -> Result<(), Error> {
    let response = Http2Client::new().request(Request::new(
        "https://example.com".to_string(),
        "GET".to_string(),
        vec![],
        None,
    ));

    match response {
        Ok(_response) => Ok(()),
        Err(e) => {
            return Err(e);
        }
    }
}
