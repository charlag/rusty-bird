#![allow(unused)]
#![allow(unused_variables)]
#![allow(unused_imports)]

extern crate hyper;
extern crate rustc_serialize;
extern crate rand;
extern crate url;
extern crate time;
extern crate crypto;

use std::io::Read;
use std::io;
use std::collections::HashMap;

use hyper::Client;
use hyper::header::Connection;
use hyper::header::{Headers, Authorization, Basic, ContentType, Bearer};

use rustc_serialize::base64;
use rustc_serialize::base64::{ToBase64, STANDARD};
use rustc_serialize::json::Json;

use url::percent_encoding;

use crypto::{hmac, sha1};
use crypto::mac::Mac;
use crypto::md5::Md5;
use crypto::digest::Digest;

use std::ascii::AsciiExt;
use rand::Rng;


fn collect_params(consumer_key: &str, nonce: &str, timestamp: &str) -> String {
    format!("oauth_callback=oob&oauth_consumer_key={}&oauth_nonce={}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={}&oauth_version=1.0",
                                    consumer_key, nonce, timestamp)
}

// Generating random BASE64-encoded string from 32 bytes of random data
fn generate_nonce() -> String {
    rand::thread_rng().gen_ascii_chars()
        .take(42).collect()
}

fn auth() {
    let url = "https://api.twitter.com/oauth/request_token";
    let consumer_key = "";
    let consumer_secret = "";
    let nonce = generate_nonce();
    let timestamp = time::get_time().sec.to_string();
    let mut collected_params = collect_params(consumer_key, &nonce, &timestamp);
    let params_for_encoding = "POST&".to_string() + &percent_encoding::utf8_percent_encode(url, percent_encoding::FORM_URLENCODED_ENCODE_SET);
    let percent_encoded_params = percent_encoding::utf8_percent_encode(&collected_params,
                                                        percent_encoding::FORM_URLENCODED_ENCODE_SET);
    let sign_base_string = params_for_encoding + "&" + &percent_encoded_params;
    let signing_key = consumer_secret.to_string() + &"&";
    let mut hm = hmac::Hmac::new(sha1::Sha1::new(), signing_key.as_bytes());
    hm.input(sign_base_string.as_bytes());
    let size = hm.output_bytes();
    let mut sign_vec = vec![0; size];
    let mut sign_slice = &mut sign_vec;
    hm.raw_result(&mut sign_slice);
    let sign = sign_slice.to_base64(base64::STANDARD);
    let sign_encoded = percent_encoding::utf8_percent_encode(&sign,
                                        percent_encoding::FORM_URLENCODED_ENCODE_SET);

    let client = Client::new();
    let mut headers = Headers::new();
    let auth_string = format!("OAuth oauth_callback=oob, oauth_consumer_key=\"{}\", oauth_nonce=\"{}\", oauth_signature=\"{}\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"{}\", oauth_version=\"1.0\"",
                        consumer_key, nonce, sign_encoded, timestamp);
    let mut auth_vec = Vec::new();
    auth_vec.extend(auth_string.as_bytes().iter());
    headers.set_raw("Authorization", vec![auth_vec]);
    //let mut req = client.post("http://requestb.in/1fbwty61?")
    let mut req = client.post("https://api.twitter.com/oauth/request_token")
        .headers(headers)
        .body("oauth_callback=oob")
        .send()
        .ok()
        .expect("Authentication error");

    let mut response = String::new();
    req.read_to_string(&mut response)
        .ok()
        .expect("Response reading error");

    println!("{}", response);
    let mut response_map = HashMap::<&str, &str>::new();
    for pair in response.split('&') {
        let mut t = pair.split('=');
        response_map.insert(t.next().unwrap(), t.next().unwrap());
    }
     println!("Token: {}", response_map.get("oauth_token").unwrap());
     println!("Token secret: {}", response_map.get("oauth_token_secret").unwrap());
    println!("https://api.twitter.com/oauth/authorize?oauth_token={}",
            response_map.get("oauth_token").unwrap());
}

fn main() {
    auth();
    return;

    let url = "https://api.twitter.com/oauth2/token";
    //let url = "http://requestb.in/1fbwty61";
    let consumer_key_and_secret = ":";
    //let consumer_secret = "";

    let base64_config = STANDARD;
    let mut encoded_secret = consumer_key_and_secret.as_bytes().to_base64(base64_config);

    // let client = Client::new();
    //
    // let mut headers = Headers::new();

    /*
    headers.set(
        Authorization(
            Basic {
                username: consumer_key.to_owned(),
                password: Some(consumer_secret.to_owned())
            }
        )
    );
    */
    // let mut auth = Vec::new();
    // auth.extend("Basic ".as_bytes().iter().cloned());
    // auth.extend(encoded_secret.as_bytes().iter().cloned());



    // headers.set_raw("Authorization", vec![auth]);
    // headers.set_raw("Content-Type", vec![b"application/x-www-form-urlencoded;charset=UTF-8".to_vec()]);

    /*
    headers.set(
            ContentType::form_url_encoded()
    );
    */

    // let mut res = client.post(url)
    //     .headers(headers)
    //     .body("grant_type=client_credentials")
    //     .send().unwrap();
    //
    // let mut body = String::new();
    // res.read_to_string(&mut body).unwrap();
    //
    // println!("Response: {}", body);

    let access_token = "";

    'outer: loop {
        let mut line = String::new();
        let client = Client::new();
        println!("Username: ");
        io::stdin().read_line(&mut line)
            .ok()
            .expect("Bye");

        let mut headers = Headers::new();
        headers.set(
            Authorization(
                Bearer {
                    token: access_token.to_owned()
                }
            )
        );

        let username = line.trim();

        let url = format!("https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name={}&exclude_replies=true",
                            username);

        let mut req = client.get(&url)
            .headers(headers)
            .send()
            .ok()
            .expect("Network error?");

            let mut response = String::new();
            req.read_to_string(&mut response)
                .ok()
                .expect("Read to string error?");

            let data = Json::from_str(&response)
                .ok()
                .expect("Json decode err");
            let arr = data.as_array();
            if arr.is_none() {
                println!("No array");
                continue;
            }

            println!("Tweets by {}", username);

            for tw in arr.unwrap() {
                let text = tw.find("text");
                if text.is_none() {
                    println!("No text");
                    continue 'outer
                }
                println!("{}", text.unwrap());
            }
    }
}
