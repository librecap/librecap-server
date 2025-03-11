use bincode;
use blake3::Hasher;
use flate2::read::GzDecoder;
use hmac::{Hmac, Mac};
use image::{DynamicImage, ImageOutputFormat, Rgb, RgbImage};
use imageproc::drawing::{draw_filled_circle_mut, draw_line_segment_mut};
use rand::seq::SliceRandom;
use rand::Rng;
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};
use serde_pickle as pickle;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub fn combine_byte_arrays(byte_arrays: &[Vec<u8>]) -> Vec<u8> {
    let total_size = byte_arrays.len() * 4 + byte_arrays.iter().map(|arr| arr.len()).sum::<usize>();
    let mut buffer = Vec::with_capacity(total_size);

    for arr in byte_arrays {
        buffer.extend_from_slice(&(arr.len() as u32).to_be_bytes());
        buffer.extend_from_slice(arr);
    }

    buffer
}

#[derive(Debug, Deserialize)]
struct PickleCaptchaData {
    #[serde(rename = "type")]
    data_type: String,
    keys: HashMap<String, Vec<pickle::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CaptchaData {
    #[serde(rename = "type")]
    data_type: String,
    keys: HashMap<String, Vec<Vec<u8>>>,
}

pub struct ImageCaptchaManager {
    data: CaptchaData,
    secret_token: [u8; 32],
}

fn get_data(dataset_path: &Path) -> Result<CaptchaData, Box<dyn std::error::Error>> {
    let cache_path = dataset_path.with_extension("cache");

    if cache_path.exists() {
        let mut file = File::open(&cache_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        return Ok(bincode::deserialize(&buffer)?);
    }

    let mut file = File::open(dataset_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let pickle_data: PickleCaptchaData = pickle::from_slice(&buffer, Default::default())?;

    if pickle_data.data_type != "image" {
        return Err("Invalid dataset format".into());
    }

    let mut data = CaptchaData {
        data_type: pickle_data.data_type,
        keys: HashMap::new(),
    };

    for (key, images) in pickle_data.keys {
        let mut processed_images = Vec::new();
        for image_value in images {
            if let pickle::Value::Bytes(compressed) = image_value {
                let mut decoder = GzDecoder::new(&compressed[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;

                let img = image::load_from_memory(&decompressed)?;
                let resized = img.resize(100, 100, image::imageops::FilterType::Triangle);

                let mut webp_data = Vec::new();
                let mut cursor = Cursor::new(&mut webp_data);
                resized.write_to(&mut cursor, ImageOutputFormat::WebP)?;

                processed_images.push(webp_data);
            }
        }
        data.keys.insert(key, processed_images);
    }

    let cache_data = bincode::serialize(&data)?;
    std::fs::write(&cache_path, cache_data)?;

    Ok(data)
}

#[derive(Debug)]
pub struct CaptchaChallenge {
    pub images: Vec<Vec<u8>>,
    pub nonce: [u8; 16],
    pub timestamp: u64,
    pub indices_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl ImageCaptchaManager {
    pub fn new(dataset_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let data = get_data(dataset_path)?;

        let mut secret_token = [0u8; 32];
        rand::thread_rng().fill(&mut secret_token);

        Ok(ImageCaptchaManager { data, secret_token })
    }

    pub fn with_secret(
        dataset_path: &Path,
        secret_token: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let data = get_data(dataset_path)?;

        Ok(ImageCaptchaManager { data, secret_token })
    }

    pub fn get_secret(&self) -> &[u8; 32] {
        &self.secret_token
    }

    pub fn generate_captcha_challenge(
        &self,
        ip: &str,
        user_agent: &str,
        mut hardness: u8,
    ) -> Result<CaptchaChallenge, Box<dyn std::error::Error>> {
        if hardness < 1 {
            hardness = 1;
        }

        let mut rng = rand::thread_rng();

        let keys: Vec<&String> = self.data.keys.keys().collect();
        let target_key = keys.choose(&mut rng).unwrap();
        let num_target = rng.gen_range(2..=4);

        let target_images = self.data.keys.get(*target_key).unwrap();
        let distractor_images: Vec<&Vec<Vec<u8>>> = self
            .data
            .keys
            .iter()
            .filter(|(k, _)| k != target_key)
            .map(|(_, v)| v)
            .collect();

        let mut selected_images = Vec::with_capacity(10);
        let mut correct_indices = Vec::with_capacity(num_target);

        let mut indices: Vec<usize> = (0..9).collect();
        indices.shuffle(&mut rng);
        let target_indices: Vec<usize> = indices.iter().take(num_target).copied().collect();

        let example_image = &target_images[rng.gen_range(0..target_images.len())];
        selected_images.push(example_image.clone());

        for _ in 0..hardness {
            for i in 0..9 {
                let is_target = target_indices.contains(&i);
                let source_images = if is_target {
                    target_images
                } else {
                    distractor_images[rng.gen_range(0..distractor_images.len())]
                };
                let image_bytes = &source_images[rng.gen_range(0..source_images.len())];

                let distorted =
                    self.manipulate_image_bytes(image_bytes, rng.gen_range(1..=hardness + 1))?;
                selected_images.push(distorted);

                if is_target {
                    correct_indices.push(i as u8);
                }
            }
        }

        correct_indices.sort_unstable();

        println!(
            "Looking for {}. Correct indices: {:?}",
            target_key, correct_indices
        );

        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut hasher = Hasher::new();
        hasher.update(&nonce);
        hasher.update(&correct_indices);
        let indices_hash = hasher.finalize();

        let mut message = Vec::new();
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(indices_hash.as_bytes());
        message.extend_from_slice(ip.as_bytes());
        message.extend_from_slice(user_agent.as_bytes());

        let signature = HmacSha256::new_from_slice(&self.secret_token)
            .expect("HMAC can take key of any size")
            .finalize()
            .into_bytes()
            .to_vec();

        Ok(CaptchaChallenge {
            images: selected_images,
            nonce,
            timestamp,
            indices_hash: indices_hash.into(),
            signature,
        })
    }

    pub fn validate_challenge(
        &self,
        selected_indices: &[u8],
        signed_data: &[u8],
        ip: &str,
        user_agent: &str,
        expiry_seconds: u64,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if signed_data.len() < 88 {
            return Ok(false);
        }

        let nonce = &signed_data[..16];
        let timestamp_bytes = &signed_data[16..24];
        let indices_hash = &signed_data[24..56];
        let signature = &signed_data[56..];

        let mut timestamp_arr = [0u8; 8];
        timestamp_arr.copy_from_slice(timestamp_bytes);
        let timestamp = u64::from_be_bytes(timestamp_arr);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time >= timestamp + expiry_seconds {
            return Ok(false);
        }

        let mut sorted_indices = selected_indices.to_vec();
        sorted_indices.sort_unstable();

        let mut hasher = Hasher::new();
        hasher.update(nonce);
        hasher.update(&sorted_indices);
        let selected_hash = hasher.finalize();

        if selected_hash.as_bytes() != indices_hash {
            return Ok(false);
        }

        let mut message = Vec::new();
        message.extend_from_slice(nonce);
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(indices_hash);
        message.extend_from_slice(ip.as_bytes());
        message.extend_from_slice(user_agent.as_bytes());

        let mut mac =
            HmacSha256::new_from_slice(&self.secret_token).expect("HMAC can take key of any size");
        mac.update(&message);

        Ok(mac.verify_slice(signature).is_ok())
    }

    pub fn manipulate_image_bytes(
        &self,
        image_data: &[u8],
        hardness: u8,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let hardness = hardness.min(5) as f32;
        let mut rng = rand::thread_rng();

        let img = image::load_from_memory(image_data)?;
        let mut img = img.to_rgb8();
        let (width, height) = img.dimensions();

        for y in 0..height {
            for x in 0..width {
                if (x + y) % 2 == 0 {
                    let pixel = img.get_pixel_mut(x, y);
                    let [r, g, b] = pixel.0;
                    pixel.0 = [
                        (r as f32 * 0.95) as u8,
                        (g as f32 * 0.95) as u8,
                        (b as f32 * 0.95) as u8,
                    ];
                }
            }
        }

        let center_x = width / 2;
        let center_y = height / 2;
        let radius = (width.min(height) / 3) as f32;

        let num_dots = rng.gen_range(10..20) * hardness as u32;
        for _ in 0..num_dots {
            let angle = rng.gen_range(0.0..std::f32::consts::TAU);
            let dist = rng.gen_range(0.0..radius);
            let x = (center_x as f32 + dist * angle.cos()) as u32;
            let y = (center_y as f32 + dist * angle.sin()) as u32;

            if x < width && y < height {
                let base_color = img.get_pixel(x, y).0;
                let color = Rgb([
                    ((base_color[0] as u32 + rng.gen_range(0..=50)) as u8).min(255),
                    ((base_color[1] as u32 + rng.gen_range(0..=50)) as u8).min(255),
                    ((base_color[2] as u32 + rng.gen_range(0..=50)) as u8).min(255),
                ]);
                draw_filled_circle_mut(&mut img, (x as i32, y as i32), 1, color);
            }
        }

        let num_lines = rng.gen_range(10..20) * hardness as u32;
        for _ in 0..num_lines {
            let angle1 = rng.gen_range(0.0..std::f32::consts::TAU);
            let angle2 = angle1 + rng.gen_range(-0.5..0.5);
            let start_x = (center_x as f32 + radius * angle1.cos()) as f32;
            let start_y = (center_y as f32 + radius * angle1.sin()) as f32;
            let end_x = (center_x as f32 + radius * angle2.cos()) as f32;
            let end_y = (center_y as f32 + radius * angle2.sin()) as f32;

            let color = Rgb([
                rng.gen_range(150..=200),
                rng.gen_range(150..=200),
                rng.gen_range(150..=200),
            ]);
            draw_line_segment_mut(&mut img, (start_x, start_y), (end_x, end_y), color);
        }

        let normal = Normal::new(0.0, (hardness * 0.5) as f64).unwrap();
        let mut shifted = RgbImage::new(width, height);

        let max_shift = (hardness * 0.2).max(1.0) as f64;

        for y in 0..height {
            for x in 0..width {
                let shift_x = (normal.sample(&mut rng) * max_shift as f64) as i32;
                let shift_y = (normal.sample(&mut rng) * max_shift as f64) as i32;

                let new_x = ((x as i32 + shift_x).rem_euclid(width as i32)) as u32;
                let new_y = ((y as i32 + shift_y).rem_euclid(height as i32)) as u32;

                shifted.put_pixel(new_x, new_y, *img.get_pixel(x, y));
            }
        }

        let intensity_factor = 1.0 + (hardness * 0.02);
        for pixel in shifted.pixels_mut() {
            let [r, g, b] = pixel.0;
            pixel.0 = [
                ((r as f32 * intensity_factor).min(255.0)) as u8,
                ((g as f32 * intensity_factor).min(255.0)) as u8,
                ((b as f32 * intensity_factor).min(255.0)) as u8,
            ];
        }

        let mut output = Vec::new();
        let mut cursor = Cursor::new(&mut output);
        DynamicImage::ImageRgb8(shifted).write_to(&mut cursor, ImageOutputFormat::WebP)?;

        Ok(output)
    }
}
