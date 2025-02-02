pub mod http1;
pub mod http2;

pub trait HttpClient {
    fn request(&self, req: Request) -> Result<Response, Error>;
}

pub struct Request {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn new(
        url: String,
        method: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Self {
        Self {
            url,
            method,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    ConnectionFailed,
    InvalidResponse,
    Timeout,
    Other(String),
}
