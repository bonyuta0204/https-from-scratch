use std::net::TcpStream;
mod http;

use http::{HttpClient, Request};
use http::http1::Http1Client;

fn main() {
    let client = Http1Client;
    let request = Request {
        method: "GET".to_string(),
        uri: "/".to_string(),
        headers: vec![],
        body: None,
    };

    match client.request(request) {
        Ok(response) => println!("Response: {:?}", response),
        Err(e) => eprintln!("Error: {:?}", e),
    }
}
