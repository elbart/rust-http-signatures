extern crate base64;
extern crate crypto;
extern crate itertools;
extern crate regex;
extern crate time;

use std::collections::HashMap;
use std::fmt;

use base64::encode as b64_encode;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use itertools::Itertools;
use time::now_utc;
use regex::Regex;

/// Simple tuple type for a HTTP Header to use along
/// with vectors. We need to use vectors instead of HashMaps
/// to maintain ordering.
struct HTTPHeader(String, String);

/// Wraps common HTTP methods
enum HTTPMethod {
    HEAD,
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    PURGE,
    CONNECT,
    OPTIONS,
    TRACE,
}

/// Implement the fmt::Display trait to be able to
/// represent all values as strings.
impl fmt::Display for HTTPMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let repr = match self {
            &HTTPMethod::HEAD => "HEAD",
            &HTTPMethod::GET => "GET",
            &HTTPMethod::POST => "POST",
            &HTTPMethod::PUT => "PUT",
            &HTTPMethod::DELETE => "DELETE",
            &HTTPMethod::PATCH => "PATCH",
            &HTTPMethod::PURGE => "PURGE",
            &HTTPMethod::CONNECT => "CONNECT",
            &HTTPMethod::OPTIONS => "OPTIONS",
            &HTTPMethod::TRACE => "TRACE",
        };

        write!(f, "{}", repr)
    }
}

/// Central HTTP Request type which is passed to an
/// HTTP Signature Implementation
struct HTTPRequest {
    headers: HashMap<String, String>,
    method: HTTPMethod,
    host_name: String,
    path: String,
    query: Option<String>,
    body: Option<String>,
}

/// Implementation for HTTP Signatures Draft-00.
/// See https://tools.ietf.org/html/draft-cavage-http-signatures-00.
/// There are more drafts, so a trait might be good to use and then
/// provide different implementations for that.
struct HTTPSignaturesImplementation {
    key_id: String,
    secret: String,
    default_headers_to_sign: Vec<String>,
}

impl HTTPSignaturesImplementation {
    fn process_headers_to_sign(&self, req: &HTTPRequest) -> Vec<HTTPHeader> {
        let mut result: Vec<HTTPHeader> = Vec::new();

        for h in self.default_headers_to_sign.iter() {
            // Iterate over the default headers and copy
            // the values of each found header in the request to the result.
            // For all not found headers, a default value is
            // assembled below.
            match req.headers.get(h) {
                // just insert the found header from the original request
                Some(val) => result.push(HTTPHeader(h.clone(), val.clone())),

                // fallback handling for not found headers
                None => match h.as_ref() {
                    "date" => result.push(HTTPHeader(
                        "date".to_string(),
                        now_utc().rfc822().to_string(),
                    )),
                    "host" => result.push(HTTPHeader("host".to_string(), req.host_name.clone())),
                    "content-md5" => match req.body {
                        Some(ref body) => if body.len() > 0 {
                            result.push(HTTPHeader(h.clone(), b64_encode(body)))
                        },
                        None => (),
                    },
                    _ => (),
                },
            };
        }

        result
    }

    fn get_signature(
        &self,
        req: &HTTPRequest,
        headers: &Vec<HTTPHeader>,
    ) -> Result<String, String> {
        let string = self.get_string_to_sign(&req, headers);
        let mut hasher = Sha256::new();
        hasher.input_str(&string.unwrap());
        Ok(b64_encode(&hasher.result_str()))
    }

    fn get_string_to_sign(
        &self,
        req: &HTTPRequest,
        headers: &Vec<HTTPHeader>,
    ) -> Result<String, String> {
        let mut query_string = String::new();

        if let Some(ref q) = req.query {
            query_string.push_str("?");
            query_string.push_str(q);
        }

        let request_line = format!("{0} {1}{2} HTTP/1.1\n", req.method, req.path, query_string);

        let mut result_string = String::new();
        result_string.push_str(&request_line);

        for header in headers.iter() {
            result_string.push_str(&format!("{0}: {1}\n", header.0, header.1));
        }

        Ok(result_string.trim().to_string())
    }

    /// Signs the passed http request and returns a signature string
    pub fn sign_request(&self, req: &HTTPRequest) -> Result<String, String> {
        let headers_to_sign = self.process_headers_to_sign(req);

        let headers_string = headers_to_sign.iter().map(|x| &x.0).join(" ");

        let signature = self.get_signature(&req, &headers_to_sign);
        let result = format!(
            concat!(
                "Signature keyId=\"{0}\",",
                "algorithm=\"hmac-sha256\",",
                "headers=\"{1}\",",
                "signature=\"{2}\""
            ),
            self.key_id,
            headers_string,
            signature.unwrap()
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn new_get_request() -> HTTPRequest {
        let headers: HashMap<String, String> = HashMap::new();

        HTTPRequest {
            headers,
            method: HTTPMethod::GET,
            host_name: "elbart.com".to_string(),
            path: "/api/services".to_string(),
            query: None,
            body: None,
        }
    }

    fn new_request(method: HTTPMethod) -> HTTPRequest {
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("date".to_string(), "2018-03-23".to_string());

        HTTPRequest {
            headers,
            method: HTTPMethod::POST,
            host_name: "elbart.com".to_string(),
            path: "/api/services".to_string(),
            query: Some("a=b&c=d".to_string()),
            body: Some("this is the body".to_string()),
        }
    }

    fn new_signature_implementation() -> HTTPSignaturesImplementation {
        let mut default_headers = Vec::new();
        default_headers.push("date".to_string());
        default_headers.push("host".to_string());
        default_headers.push("content-md5".to_string());

        HTTPSignaturesImplementation {
            key_id: "mykey".to_string(),
            secret: "mysecret".to_string(),
            default_headers_to_sign: default_headers,
        }
    }

    #[test]
    fn test_process_headers_to_sign_get() {
        let request = new_get_request();
        let signer = new_signature_implementation();

        let result = signer.process_headers_to_sign(&request);
        assert_eq!(result.len(), 2);

        assert_eq!(result[0].0, "date");

        let re = Regex::new(r"^[\w]{3}, \d{1,2} [\w]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$").unwrap();
        assert!(re.is_match(&result[0].1));
        assert_eq!(&result[1].1, "elbart.com");
    }

    #[test]
    fn test_process_headers_to_sign_post() {
        let request = new_request(HTTPMethod::POST);
        let signer = new_signature_implementation();

        let result = signer.process_headers_to_sign(&request);
        assert_eq!(result.len(), 3);

        assert_eq!(&result[0].1, "2018-03-23");
        assert_eq!(&result[1].1, "elbart.com");
        assert_eq!(&result[2].1, &b64_encode("this is the body"));
    }

    #[test]
    fn test_get_string_to_sign() {
        let request = new_request(HTTPMethod::POST);
        let signer = new_signature_implementation();

        let headers = signer.process_headers_to_sign(&request);
        let result = signer.get_string_to_sign(&request, &headers);

        assert_eq!(result.unwrap(), "POST /api/services?a=b&c=d HTTP/1.1\ndate: 2018-03-23\nhost: elbart.com\ncontent-md5: dGhpcyBpcyB0aGUgYm9keQ==");
    }

    #[test]
    fn test_sign_request() {
        let request = new_request(HTTPMethod::POST);
        let signer = new_signature_implementation();

        let result = signer.sign_request(&request);

        assert_eq!(result.unwrap(), "Signature keyId=\"mykey\",algorithm=\"hmac-sha256\",headers=\"date host content-md5\",signature=\"ZWE0ZTRkYmYzMTlkZWEyMGQwN2Q2NDY3MGQ1MzZiN2FjZjNhOWZjNGRkNDhlNTNlM2QxMDMzYTQ3ZTQ0NzY4Zg==\"");
    }
}
