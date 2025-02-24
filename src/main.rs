mod http;

use http::http2::Http2Client;
use http::{Error, HttpClient, Request};

fn main() -> Result<(), Error> {
    // Create a new HTTP/2 client and make a request
    let client = Http2Client::new();
    
    // Send a GET request to Google
    let response = client.request(Request::new(
        "https://www.google.com".to_string(),
        "GET".to_string(),
        vec![
            // Add some custom headers
            ("user-agent".to_string(), "https-from-scratch/0.1.0".to_string()),
            ("accept".to_string(), "*/*".to_string()),
        ],
        None, // No body for GET request
    ));

    match response {
        Ok(response) => {
            // Print the response
            println!("\n===== Response Summary =====");
            println!("Status: {}", response.status);
            println!("Headers:");
            for (name, value) in &response.headers {
                println!("  {}: {}", name, value);
            }
            println!("Body length: {} bytes", response.body.len());
            
            // Print the start of the response body as text if it appears to be text
            if response.body.len() > 0 {
                let preview_len = std::cmp::min(response.body.len(), 200);
                println!("\nBody preview:\n{}", String::from_utf8_lossy(&response.body[0..preview_len]));
                if response.body.len() > preview_len {
                    println!("... (truncated)");
                }
            }
            
            Ok(())
        },
        Err(e) => {
            eprintln!("Error: {:?}", e);
            Err(e)
        }
    }
}
