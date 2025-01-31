pub mod http1;

pub trait HttpClient {
    fn request(&self, req: Request) -> Result<Response, Error>;
}

pub struct Request {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    ConnectionFailed,
    InvalidResponse,
    Timeout,
    Other(String),
}
