use base64::{engine, Engine};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Url;
use std::collections::HashMap;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    extern crate dotenv;
    dotenv::dotenv().expect("Failed to read .env file");

    let client_id = env::var("client_id")?;
    let client_secret = env::var("client_secret")?;
    let redirect_uri = ("http://localhost:3000");

    let auth_string = format!("{}:{}", client_id, client_secret);
    let auth_base64 = engine::general_purpose::STANDARD.encode(auth_string); // Oh brother this shit stinks
                                                                             //let auth_base64 = base64::encode(auth_string); //old mf code

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Basic {}", auth_base64).parse().unwrap(),
    );
    headers.insert(
        CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );

    let mut params = HashMap::new();
    params.insert("grant_type", "client_credentials");

    let url = Url::parse("https://accounts.spotify.com/api/token")?;
    let client = reqwest::Client::new();
    let result = client
        .post(url)
        .headers(headers)
        .form(&params)
        .send()
        .await?;

    //println!("{}", format!("{:?}", result));

    let access_token = result.json::<serde_json::Value>().await?["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    println!("{}", access_token);

    Ok(())
}

/*
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_id = env::var("c103fd4390eb403eb313c64339186059")?;
    let client_secret = env::var("71d186ae9f554cf0857f98d323152947")?;
    let redirect_uri = env::var("http://localhost:3000")?;
    let code = "authorization_code"; // Replace with the authorization code obtained from the user


    let client = reqwest::Client::new();
    let response = client
        .post("https://accounts.spotify.com/api/token")
        .header("Authorization", format!("Basic {}", base64::encode(format!("{}:{}", client_id, client_secret))))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&[
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await?
        .json::<TokenResponse>()
        .await?;

    println!("Access token: {}", response.access_token);
    println!("Token type: {}", response.token_type);
    println!("Expires in: {}", response.expires_in);
    println!("Refresh token: {:?}", response.refresh_token);
    println!("Scope: {:?}", response.scope);

    Ok(()) // not strictly nessesary, but is a common idiom
}
 */

/*
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let search_query = &args[1];
    let url = format!(
        "https://api.spotify.com/v1/search?q={query}&type=track,artist",
        query = search_query
    );

    let client_id = env::var("c103fd4390eb403eb313c64339186059")?;
    let client_secret = env::var("71d186ae9f554cf0857f98d323152947")?;
    let redirect_uri = env::var("https://github.com/KoksILasten")?;
    let code = "authorization_code"; // Replace with the authorization code obtained from the user


    let client = reqwest::Client::new();
    let response = client
        .post("https://accounts.spotify.com/api/token")
        .header("Authorization", format!("Basic {}", base64::encode(format!("{}:{}", client_id, client_secret))))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await?
        .json::<TokenResponse>()
        .await?;

       let oaut = response.access_token;

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header(AUTHORIZATION, format!("Bearer {}", oaut))
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .send()
        .await?;

    match response.status() {
        reqwest::StatusCode::OK => {
            let parsed = response.json::<APIResponse>().await?;
            print_tracks(parsed.tracks.items.iter().collect());
        }
        reqwest::StatusCode::UNAUTHORIZED => {
            println!("UNAUTHORIZED: GRAB A NEW TOKEN")
        }
        _ => {
            println!("Unexpected status code: {:?}", response.status());
        }
    };

    Ok(())
}
 */
/*
#[tokio::main]
async fn main(){
    let args: Vec<String> = env::args().collect();
    let search_query = &args[1];
    let auth_token = &args[2];
    let url = format!(
        "https://api.spotify.com/v1/search?q={query}&type=track,artist",
        query = search_query
    );
    let client = reqwest::Client::new();
    let response = client
    .get(url)
    .header(AUTHORIZATION, format!("Bearer {} ", auth_token))
    .header(CONTENT_TYPE, "application/json")
    .header(ACCEPT, "application/json")
    .send()
    .await
    .unwrap();

match response.status() {
    reqwest::StatusCode::OK => {
        match response.json::<APIResponse>().await {
            Ok(parsed) => print_tracks(parsed.tracks.items.iter().collect()),
            Err(_) => println!("the response didnt match the shape of the struct")
        };
    }
    reqwest::StatusCode::UNAUTHORIZED => {
        println!( "UNAUTHORIZED: GRAB A NEW TOKEN")
    }
    _ => {
        println!("Unexpected status code: {:?}", response.status());
    }
};
}
*/
