use super::{Error, HttpClient, Request, Response};
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct Http1Client;

impl HttpClient for Http1Client {
    fn request(&self, req: Request) -> Result<Response, Error> {
        let mut stream =
            TcpStream::connect("www.google.com:80").map_err(|_| Error::ConnectionFailed)?;

        // Build HTTP request
        let request_line = format!("{} {} HTTP/1.1\r\n", req.method, req.url);
        let headers = req
            .headers
            .iter()
            .map(|(k, v)| format!("{}: {}\r\n", k, v))
            .collect::<String>();
        let body = req.body.unwrap_or_default();

        // Send request
        stream
            .write_all(request_line.as_bytes())
            .map_err(|e| Error::Other(e.to_string()))?;
        stream
            .write_all(headers.as_bytes())
            .map_err(|e| Error::Other(e.to_string()))?;
        stream
            .write_all(b"\r\n")
            .map_err(|e| Error::Other(e.to_string()))?;
        stream
            .write_all(&body)
            .map_err(|e| Error::Other(e.to_string()))?;

        // Read response
        let mut buffer = [0; 4096];
        let bytes_read = stream
            .read(&mut buffer)
            .map_err(|e| Error::Other(e.to_string()))?;

        // Parse response (basic parsing for now)
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
        let mut lines = response.lines();

        let status_line = lines.next().ok_or(Error::InvalidResponse)?;
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or(Error::InvalidResponse)?;

        Ok(Response {
            status,
            headers: Vec::new(), // TODO: Parse headers
            body: buffer[..bytes_read].to_vec(),
        })
    }
}
