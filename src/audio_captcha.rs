use bincode;
use blake3::Hasher;
use hmac::{Hmac, Mac};
use hound::{SampleFormat, WavSpec, WavWriter};
use lame::Lame;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use rand_distr::{Distribution, Normal, Uniform};
use serde::{Deserialize, Serialize};
use serde_pickle as pickle;
use sha2::Sha256;
use std::collections::HashMap;
use std::f32::consts::PI;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const WAVE_SAMPLE_RATE: u32 = 44100;

#[derive(Debug, Deserialize)]
struct PickleCaptchaData {
    #[serde(rename = "type")]
    data_type: String,
    #[serde(rename = "keys")]
    keys: HashMap<String, HashMap<String, pickle::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CaptchaData {
    #[serde(rename = "type")]
    data_type: String,
    keys: HashMap<String, HashMap<String, Vec<u8>>>,
}

#[derive(Debug)]
pub struct CaptchaChallenge {
    pub audio_data: Vec<u8>,
    pub characters: Vec<String>,
    pub character_type: String,
    pub language: String,
    pub instruction: String,
    pub obfuscated: bool,
    pub nonce: [u8; 16],
    pub timestamp: u64,
    pub indices_hash: [u8; 32],
    pub signature: Vec<u8>,
}

pub struct AudioCaptchaManager {
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

    if pickle_data.data_type != "audio" {
        return Err("Invalid dataset format".into());
    }

    let mut processed_data = CaptchaData {
        data_type: pickle_data.data_type,
        keys: HashMap::new(),
    };

    for (key, lang_map) in pickle_data.keys {
        let mut processed_lang_map = HashMap::new();
        for (lang, value) in lang_map {
            if let pickle::Value::Bytes(bytes) = value {
                processed_lang_map.insert(lang, bytes);
            } else {
                return Err("Invalid audio data format".into());
            }
        }
        processed_data.keys.insert(key, processed_lang_map);
    }

    let cache_data = bincode::serialize(&processed_data)?;
    std::fs::write(&cache_path, cache_data)?;

    Ok(processed_data)
}

impl AudioCaptchaManager {
    pub fn new(dataset_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let data = get_data(dataset_path)?;

        let mut secret_token = [0u8; 32];
        thread_rng().fill(&mut secret_token);

        Ok(AudioCaptchaManager { data, secret_token })
    }

    pub fn with_secret(
        dataset_path: &Path,
        secret_token: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let data = get_data(dataset_path)?;

        Ok(AudioCaptchaManager { data, secret_token })
    }

    pub fn get_secret(&self) -> &[u8; 32] {
        &self.secret_token
    }

    fn create_silence(&self, duration_ms: u32) -> Vec<i16> {
        vec![0i16; (WAVE_SAMPLE_RATE * duration_ms / 1000) as usize]
    }

    fn create_noise(&self, duration_ms: u32, level: f32) -> Vec<i16> {
        let num_samples = (WAVE_SAMPLE_RATE * duration_ms / 1000) as usize;
        let dist = Uniform::new(-1.0f32, 1.0);
        let mut rng = thread_rng();

        (0..num_samples)
            .map(|_| (dist.sample(&mut rng) * level * 32767.0) as i16)
            .collect()
    }

    fn change_speed(&self, samples: &[i16], speed: f32) -> Vec<i16> {
        if (speed - 1.0).abs() < f32::EPSILON {
            return samples.to_vec();
        }

        let new_len = (samples.len() as f32 / speed) as usize;
        let mut result = Vec::with_capacity(new_len);

        for i in 0..new_len {
            let pos = i as f32 * speed;
            let pos_floor = pos.floor() as usize;
            let pos_ceil = pos.ceil() as usize;

            if pos_ceil >= samples.len() {
                break;
            }

            if pos_floor == pos_ceil {
                result.push(samples[pos_floor]);
            } else {
                let frac = pos - pos_floor as f32;
                let sample =
                    samples[pos_floor] as f32 * (1.0 - frac) + samples[pos_ceil] as f32 * frac;
                result.push(sample as i16);
            }
        }

        result
    }

    fn change_volume(&self, samples: &[i16], level: f32) -> Vec<i16> {
        if (level - 1.0).abs() < f32::EPSILON {
            return samples.to_vec();
        }

        samples
            .iter()
            .map(|&s| (s as f32 * level).min(32767.0).max(-32767.0) as i16)
            .collect()
    }

    fn add_background_noise(&self, samples: &[i16], noise_level: f32) -> Vec<i16> {
        let noise = self.create_noise(
            (samples.len() * 1000 / WAVE_SAMPLE_RATE as usize) as u32,
            noise_level,
        );

        samples
            .iter()
            .zip(noise.iter())
            .map(|(&s, &n)| {
                let mixed = s as f32 + n as f32;
                mixed.min(32767.0).max(-32767.0) as i16
            })
            .collect()
    }

    fn reverse_audio(&self, samples: &[i16]) -> Vec<i16> {
        let mut result = samples.to_vec();
        result.reverse();
        result
    }

    fn mix_audio(&self, base: &[i16], overlay: &[i16], position: usize) -> Vec<i16> {
        let mut result = base.to_vec();

        if position >= result.len() {
            println!(
                "WARNING: Trying to mix at position {} which is beyond the base audio length {}",
                position,
                result.len()
            );
            return result;
        }

        let mut mixed_count = 0;

        for (i, &sample) in overlay.iter().enumerate() {
            if position + i < result.len() {
                if sample != 0 {
                    mixed_count += 1;
                }
                let mixed = result[position + i] as f32 + sample as f32;
                result[position + i] = mixed.min(32767.0).max(-32767.0) as i16;
            }
        }

        if overlay.len() > 100 && mixed_count > 0 {
            println!(
                "Mixed {} non-zero samples from overlay of length {}",
                mixed_count,
                overlay.len()
            );
        }

        result
    }

    fn batch_mix_audio(
        &self,
        base: &[i16],
        segments_with_positions: &[(Vec<i16>, usize)],
    ) -> Vec<i16> {
        let mut result = base.to_vec();

        let mut sorted_segments = segments_with_positions.to_vec();
        sorted_segments.sort_by_key(|s| s.1);

        println!("Batch mixing {} segments", sorted_segments.len());

        for (i, (segment, position)) in sorted_segments.iter().enumerate() {
            let non_zero_before = result.iter().filter(|&&s| s != 0).count();

            result = self.mix_audio(&result, segment, *position);

            let non_zero_after = result.iter().filter(|&&s| s != 0).count();
            println!(
                "  Mixed segment {}: {} samples at position {}. Non-zero samples: {} -> {}",
                i,
                segment.len(),
                position,
                non_zero_before,
                non_zero_after
            );
        }

        let final_non_zero = result.iter().filter(|&&s| s != 0).count();
        println!(
            "Final mix result: {} samples, {} non-zero ({:.2}%)",
            result.len(),
            final_non_zero,
            100.0 * final_non_zero as f32 / result.len() as f32
        );

        result
    }

    fn generate_human_sound(&self, sound_type: &str, duration_ms: Option<u32>) -> Vec<i16> {
        let mut rng = thread_rng();
        let duration = duration_ms.unwrap_or_else(|| rng.gen_range(200..600));
        let num_samples = (WAVE_SAMPLE_RATE * duration / 1000) as usize;
        let t_step = 1.0 / WAVE_SAMPLE_RATE as f32;

        let mut result_samples = match sound_type {
            "speech" => {
                let base_freq = rng.gen_range(80..255) as f32;
                let mut samples = vec![0i16; num_samples];

                let frequencies = [
                    (base_freq, 1.0),
                    (base_freq * 2.0, 0.5),
                    (base_freq * 3.0, 0.25),
                    (rng.gen_range(300.0..800.0), 0.7),
                    (rng.gen_range(800.0..1800.0), 0.5),
                    (rng.gen_range(1800.0..2800.0), 0.3),
                ];

                for (freq, amp) in frequencies.iter() {
                    let fm_rate = rng.gen_range(2.0..8.0);
                    let fm_depth = rng.gen_range(5.0..15.0);

                    for i in 0..num_samples {
                        let t = i as f32 * t_step;
                        let freq_mod = freq + (2.0 * PI * fm_rate * t).sin() * fm_depth;
                        let am_depth = 0.5 + (2.0 * PI * (fm_rate + 1.0) * t).sin() * 0.5;

                        let sample = (2.0 * PI * freq_mod * t).sin() * am_depth * amp;
                        samples[i] = (samples[i] as f32 + sample * 32767.0)
                            .min(32767.0)
                            .max(-32767.0) as i16;
                    }
                }

                samples
            }
            "whisper" => {
                let normal = Normal::new(0.0, 0.3).unwrap();
                let mut rng = thread_rng();
                let mut samples = vec![0i16; num_samples];

                for i in 0..num_samples {
                    samples[i] = (normal.sample(&mut rng) * 0.7 * 32767.0) as i16;
                }

                let formants = [
                    (rng.gen_range(500.0..1000.0), 0.5),
                    (rng.gen_range(1500.0..2500.0), 0.7),
                    (rng.gen_range(3000.0..4500.0), 0.4),
                ];

                for (freq, amp) in formants.iter() {
                    for i in 0..num_samples {
                        let t = i as f32 * t_step;
                        let formant = (2.0 * PI * freq * t).sin() * amp;
                        let sample = formant * (samples[i] as f32 / 32767.0) * 0.3 * 32767.0;
                        samples[i] = (samples[i] as f32 + sample).min(32767.0).max(-32767.0) as i16;
                    }
                }

                samples
            }
            "throat" => {
                let base_freq = rng.gen_range(40.0..100.0);
                let mut samples = vec![0i16; num_samples];

                for (i, amp) in [1.0, 0.7, 0.5, 0.2].iter().enumerate() {
                    let freq = base_freq * (i as f32 + 1.0);

                    for j in 0..num_samples {
                        let t = j as f32 * t_step;
                        let sample = (2.0 * PI * freq * t).sin() * amp * 32767.0;
                        samples[j] = (samples[j] as f32 + sample).min(32767.0).max(-32767.0) as i16;
                    }
                }

                let burst_pos = (num_samples as f32 * 0.3) as usize;
                let burst_length = (WAVE_SAMPLE_RATE as f32 * 0.03) as usize;
                if burst_pos + burst_length <= num_samples {
                    let normal = Normal::new(0.0, 1.0).unwrap();
                    let mut burst = vec![0i16; burst_length];

                    for i in 0..burst_length {
                        burst[i] = (normal.sample(&mut rng) * 1.5 * 32767.0) as i16;
                    }

                    let third_length = burst_length / 3;
                    for i in 0..third_length {
                        let env = i as f32 / third_length as f32;
                        burst[i] = (burst[i] as f32 * env) as i16;
                    }

                    for i in burst_length - third_length..burst_length {
                        let env = (burst_length - i) as f32 / third_length as f32;
                        burst[i] = (burst[i] as f32 * env) as i16;
                    }

                    for i in 0..burst_length {
                        samples[burst_pos + i] = (samples[burst_pos + i] as f32 + burst[i] as f32)
                            .min(32767.0)
                            .max(-32767.0) as i16;
                    }
                }

                samples
            }
            "click" => {
                let mut samples = vec![0i16; num_samples];
                let click_pos = (num_samples as f32 * 0.2) as usize;
                let click_length = (WAVE_SAMPLE_RATE as f32 * 0.02) as usize;

                if click_pos + click_length <= num_samples {
                    let click_freq = rng.gen_range(1000.0..3000.0);

                    for i in 0..click_length {
                        let t = i as f32 * t_step;
                        let env = (i as f32 / click_length as f32)
                            * (1.0 - i as f32 / click_length as f32)
                            * 4.0;
                        samples[click_pos + i] =
                            ((2.0 * PI * click_freq * t).sin() * env * 32767.0) as i16;
                    }
                }

                samples
            }
            "hum" => {
                let notes = [110.0, 146.83, 196.0, 220.0, 261.63, 293.66, 329.63, 392.0];
                let base_freq = notes[rng.gen_range(0..notes.len())];

                let vibrato_rate = 5.0;
                let vibrato_depth = base_freq * 0.03;
                let mut samples = vec![0i16; num_samples];

                for i in 0..num_samples {
                    let t = i as f32 * t_step;
                    let freq_with_vibrato =
                        base_freq + vibrato_depth * (2.0 * PI * vibrato_rate * t).sin();

                    let mut sample = (2.0 * PI * freq_with_vibrato * t).sin();

                    for j in 2..5 {
                        let harmonic_amp = 1.0 / j as f32;
                        sample +=
                            (2.0 * PI * j as f32 * freq_with_vibrato * t).sin() * harmonic_amp;
                    }

                    samples[i] = (sample * 32767.0) as i16;
                }

                samples
            }
            "breath" => {
                let normal = Normal::new(0.0, 1.0).unwrap();
                let mut samples = vec![0i16; num_samples];

                for i in 0..num_samples {
                    samples[i] = (normal.sample(&mut rng) * 0.2 * 32767.0) as i16;
                }

                let resonances = [
                    (rng.gen_range(300.0..800.0), 0.6),
                    (rng.gen_range(1000.0..1800.0), 0.4),
                    (rng.gen_range(2000.0..3000.0), 0.2),
                ];

                for (freq, amp) in resonances.iter() {
                    for i in 0..num_samples {
                        let t = i as f32 * t_step;
                        let resonance = (2.0 * PI * freq * t).sin()
                            * (samples[i] as f32 / 32767.0)
                            * amp
                            * 32767.0;
                        samples[i] =
                            (samples[i] as f32 + resonance).min(32767.0).max(-32767.0) as i16;
                    }
                }

                samples
            }
            _ => self.create_noise(duration, 0.1),
        };

        let attack = (num_samples as f32 * 0.2) as usize;
        let decay = (num_samples as f32 * 0.3) as usize;

        if attack > 0 {
            for i in 0..attack.min(num_samples) {
                let env = i as f32 / attack as f32;
                result_samples[i] = (result_samples[i] as f32 * env) as i16;
            }
        }

        if decay > 0 {
            for i in 0..decay.min(num_samples) {
                let pos = num_samples - i - 1;
                let env = i as f32 / decay as f32;
                result_samples[pos] = (result_samples[pos] as f32 * env) as i16;
            }
        }

        result_samples
    }

    fn apply_audio_effects(&self, samples: &[i16], effect_level: &str) -> Vec<i16> {
        let mut rng = thread_rng();
        let mut result = samples.to_vec();

        match effect_level {
            "minimal" => {
                let speed = rng.gen_range(0.98..1.02);
                result = self.change_speed(&result, speed);

                let noise_level = rng.gen_range(0.003..0.008);
                result = self.add_background_noise(&result, noise_level);
            }
            "low" => {
                let (speed_range, volume_range) = ((95, 105), (95, 105));
                let speed = (rng.gen_range(speed_range.0..speed_range.1) as f32) / 100.0;
                let volume = (rng.gen_range(volume_range.0..volume_range.1) as f32) / 100.0;

                result = self.change_speed(&result, speed);
                result = self.change_volume(&result, volume);

                if rng.gen_bool(0.5) {
                    let noise_level = (rng.gen_range(1..=5) as f32) / 100.0;
                    result = self.add_background_noise(&result, noise_level);
                }

                if effect_level != "low" && rng.gen_bool(0.3) {
                    let reverb_level = (rng.gen_range(5..25) as f32) / 100.0;
                    let reverb_delay = rng.gen_range(50..150);

                    let silence = vec![0i16; reverb_delay as usize];
                    let reverb_tail = self.change_volume(samples, reverb_level);
                    let mut delayed_reverb = silence.clone();
                    delayed_reverb.extend(reverb_tail);

                    result = self.mix_audio(&result, &delayed_reverb, 0);
                }

                if effect_level == "high" && rng.gen_bool(0.2) {
                    let segment_len = result.len() / 3;
                    if segment_len > 0 {
                        let segment_start = rng.gen_range(0..result.len() - segment_len);
                        let segment = result[segment_start..segment_start + segment_len].to_vec();
                        let reversed = self.reverse_audio(&segment);

                        for (i, sample) in reversed.iter().enumerate() {
                            if segment_start + i < result.len() {
                                result[segment_start + i] = *sample;
                            }
                        }
                    }
                }
            }
            _ => {
                let (speed_range, volume_range) = match effect_level {
                    "high" => ((70, 130), (70, 130)),
                    _ => ((80, 120), (80, 120)),
                };

                let speed = (rng.gen_range(speed_range.0..speed_range.1) as f32) / 100.0;
                let volume = (rng.gen_range(volume_range.0..volume_range.1) as f32) / 100.0;

                result = self.change_speed(&result, speed);
                result = self.change_volume(&result, volume);

                if rng.gen_bool(0.5) {
                    let noise_level = (rng.gen_range(1..=5) as f32) / 100.0;
                    result = self.add_background_noise(&result, noise_level);
                }

                if effect_level != "low" && rng.gen_bool(0.3) {
                    let reverb_level = (rng.gen_range(5..25) as f32) / 100.0;
                    let reverb_delay = rng.gen_range(50..150);

                    let silence = vec![0i16; reverb_delay as usize];
                    let reverb_tail = self.change_volume(samples, reverb_level);
                    let mut delayed_reverb = silence.clone();
                    delayed_reverb.extend(reverb_tail);

                    result = self.mix_audio(&result, &delayed_reverb, 0);
                }

                if effect_level == "high" && rng.gen_bool(0.2) {
                    let segment_len = result.len() / 3;
                    if segment_len > 0 {
                        let segment_start = rng.gen_range(0..result.len() - segment_len);
                        let segment = result[segment_start..segment_start + segment_len].to_vec();
                        let reversed = self.reverse_audio(&segment);

                        for (i, sample) in reversed.iter().enumerate() {
                            if segment_start + i < result.len() {
                                result[segment_start + i] = *sample;
                            }
                        }
                    }
                }
            }
        }

        result
    }

    fn save_audio_to_bytes(
        &self,
        samples: &[i16],
        format: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let has_sound = samples.iter().any(|&s| s != 0);

        let samples_to_use = if !has_sound {
            let mut rng = thread_rng();
            let noise_duration = 2000;
            let num_samples = (WAVE_SAMPLE_RATE * noise_duration / 1000) as usize;
            let mut noise_samples = vec![0i16; num_samples];

            for i in 0..num_samples {
                noise_samples[i] = ((rng.gen::<f32>() * 2.0 - 1.0) * 3000.0) as i16;
            }

            noise_samples
        } else {
            samples.to_vec()
        };

        match format {
            "wav" => {
                let spec = WavSpec {
                    channels: 1,
                    sample_rate: WAVE_SAMPLE_RATE,
                    bits_per_sample: 16,
                    sample_format: SampleFormat::Int,
                };

                let mut buffer = Cursor::new(Vec::new());
                {
                    let mut writer = WavWriter::new(&mut buffer, spec)?;
                    for &sample in &samples_to_use {
                        writer.write_sample(sample)?;
                    }
                    writer.finalize()?;
                }

                Ok(buffer.into_inner())
            }
            "mp3" => {
                let mut lame = Lame::new().expect("Failed to initialize LAME encoder");

                lame.set_channels(1).expect("Failed to set channels");
                lame.set_sample_rate(WAVE_SAMPLE_RATE)
                    .expect("Failed to set sample rate");
                lame.set_quality(2).expect("Failed to set quality");
                lame.init_params().expect("Failed to initialize parameters");

                let pcm_right = vec![0i16; samples_to_use.len()];

                let mp3_buffer_size = (1.25 * (samples_to_use.len() as f32)) as usize + 7200;
                let mut mp3_buffer = vec![0u8; mp3_buffer_size];

                let encoded_size = lame
                    .encode(&samples_to_use, &pcm_right, &mut mp3_buffer)
                    .expect("Failed to encode MP3 data");

                mp3_buffer.truncate(encoded_size);

                Ok(mp3_buffer)
            }
            _ => Err(format!(
                "Unsupported audio format: {}. Only WAV and MP3 formats are supported.",
                format
            )
            .into()),
        }
    }

    pub fn generate_character_challenge(
        &self,
        ip: &str,
        user_agent: &str,
        character_type: &str,
        language: &str,
        count: usize,
        output_format: &str,
        obfuscate: bool,
    ) -> Result<CaptchaChallenge, Box<dyn std::error::Error>> {
        let mut rng = thread_rng();

        let mut available_numbers = Vec::new();
        let mut available_letters = Vec::new();

        println!("Available keys in data: {}", self.data.keys.len());

        for (char_key, langs) in &self.data.keys {
            if langs.contains_key(language) {
                if char_key.chars().all(|c| c.is_ascii_digit()) {
                    available_numbers.push(char_key.clone());
                } else if char_key.chars().all(|c| c.is_ascii_lowercase()) {
                    available_letters.push(char_key.clone());
                }
            }
        }

        println!(
            "Available numbers for {}: {}",
            language,
            available_numbers.len()
        );
        println!(
            "Available letters for {}: {}",
            language,
            available_letters.len()
        );

        if character_type == "numbers" && available_numbers.len() < count {
            return Err(format!(
                "Not enough number characters available in {}. Need {}, found {}.",
                language,
                count,
                available_numbers.len()
            )
            .into());
        }

        if character_type == "letters" && available_letters.len() < count {
            return Err(format!(
                "Not enough letter characters available in {}. Need {}, found {}.",
                language,
                count,
                available_letters.len()
            )
            .into());
        }

        if character_type == "mixed" && (available_numbers.len() + available_letters.len()) < count
        {
            return Err(format!(
                "Not enough characters available in {}. Need {}, found {}.",
                language,
                count,
                available_numbers.len() + available_letters.len()
            )
            .into());
        }

        let selected_chars = match character_type {
            "numbers" => available_numbers
                .choose_multiple(&mut rng, count)
                .cloned()
                .collect(),
            "letters" => available_letters
                .choose_multiple(&mut rng, count)
                .cloned()
                .collect(),
            _ => {
                let num_count = rng.gen_range(1..count.min(available_numbers.len()));
                let letter_count = count - num_count;

                let mut chars: Vec<String> = available_numbers
                    .choose_multiple(&mut rng, num_count)
                    .cloned()
                    .chain(
                        available_letters
                            .choose_multiple(&mut rng, letter_count)
                            .cloned(),
                    )
                    .collect();
                chars.shuffle(&mut rng);
                chars
            }
        };

        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut hasher = Hasher::new();
        hasher.update(&nonce);
        hasher.update(selected_chars.join("").as_bytes());
        let indices_hash = hasher.finalize();

        let mut message = Vec::new();
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(indices_hash.as_bytes());
        message.extend_from_slice(ip.as_bytes());
        message.extend_from_slice(user_agent.as_bytes());

        let mut mac =
            HmacSha256::new_from_slice(&self.secret_token).expect("HMAC can take key of any size");
        mac.update(&message);
        let signature = mac.finalize().into_bytes().to_vec();

        let intro_silence_duration = rng.gen_range(1200..2000);
        let intro_silence = self.create_silence(intro_silence_duration);

        let mut character_segments = Vec::new();
        let mut has_valid_audio = false;

        println!("Selected characters: {:?}", selected_chars);

        for (idx, char_key) in selected_chars.iter().enumerate() {
            println!("Processing character {}: {}", idx, char_key);

            if let Some(char_audio) = self
                .data
                .keys
                .get(char_key)
                .and_then(|langs| langs.get(language))
            {
                println!("  Found audio data: {} bytes", char_audio.len());

                let audio = if char_audio.len() >= 2 {
                    let audio_samples = char_audio
                        .chunks_exact(2)
                        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect::<Vec<_>>();

                    let non_zero_count = audio_samples.iter().filter(|&&s| s != 0).count();
                    println!(
                        "  Converted to {} samples, {} non-zero",
                        audio_samples.len(),
                        non_zero_count
                    );

                    if non_zero_count > 0 {
                        has_valid_audio = true;
                    }

                    audio_samples
                } else {
                    println!("  Audio data too small, generating tone");
                    let char_freq = match char_key.chars().next() {
                        Some(c) if c.is_ascii_digit() => 700.0 + (c as u8 - b'0') as f32 * 50.0,
                        Some(c) if c.is_ascii_lowercase() => 300.0 + (c as u8 - b'a') as f32 * 20.0,
                        _ => 500.0,
                    };

                    let tone_duration = 300;
                    let num_samples = (WAVE_SAMPLE_RATE * tone_duration / 1000) as usize;
                    let mut tone = vec![0i16; num_samples];

                    for i in 0..num_samples {
                        let t = i as f32 / WAVE_SAMPLE_RATE as f32;
                        tone[i] = ((2.0 * PI * char_freq * t).sin() * 0.7 * 32767.0) as i16;
                    }

                    println!("  Generated tone with {} samples", tone.len());
                    has_valid_audio = true;
                    tone
                };

                let processed_audio = audio;

                character_segments.push(processed_audio);
            } else {
                println!("  No audio data found, generating default tone");
                let char_freq = 440.0;
                let tone_duration = 300;
                let num_samples = (WAVE_SAMPLE_RATE * tone_duration / 1000) as usize;
                let mut tone = vec![0i16; num_samples];

                for i in 0..num_samples {
                    let t = i as f32 / WAVE_SAMPLE_RATE as f32;
                    tone[i] = ((2.0 * PI * char_freq * t).sin() * 0.7 * 32767.0) as i16;
                }

                println!("  Generated default tone with {} samples", tone.len());
                has_valid_audio = true;
                character_segments.push(tone);
            }
        }

        println!("Character segments: {}", character_segments.len());

        if !has_valid_audio {
            println!("No valid audio found, generating beep sequence");
            character_segments.clear();

            for (i, _) in selected_chars.iter().enumerate() {
                let char_freq = 440.0 + (i as f32 * 100.0);
                let tone_duration = 300;
                let num_samples = (WAVE_SAMPLE_RATE * tone_duration / 1000) as usize;
                let mut tone = vec![0i16; num_samples];

                for j in 0..num_samples {
                    let t = j as f32 / WAVE_SAMPLE_RATE as f32;
                    tone[j] = ((2.0 * PI * char_freq * t).sin() * 0.7 * 32767.0) as i16;
                }

                println!("  Generated beep {} with {} samples", i, tone.len());
                character_segments.push(tone);
            }
        }

        let mut segments_with_positions = Vec::new();
        let mut current_position = intro_silence.len();

        for (i, segment) in character_segments.iter().enumerate() {
            segments_with_positions.push((segment.clone(), current_position));
            println!(
                "Positioned segment {} at sample position {}",
                i, current_position
            );

            let padding_duration = rng.gen_range(1500..2500);
            current_position +=
                segment.len() + (WAVE_SAMPLE_RATE as usize * padding_duration / 1000);
        }

        let outro_silence_duration = rng.gen_range(1500..2000);
        let total_length =
            current_position + (WAVE_SAMPLE_RATE as usize * outro_silence_duration / 1000);
        println!(
            "Total audio length: {} samples ({:.2} seconds)",
            total_length,
            total_length as f32 / WAVE_SAMPLE_RATE as f32
        );
        let mut combined_audio = vec![0i16; total_length];

        combined_audio = self.batch_mix_audio(&combined_audio, &segments_with_positions);

        if obfuscate {
            let mut distractors = Vec::new();

            let num_distractors = 3 * count + rng.gen_range(2..6);
            let sound_types = [
                "speech", "whisper", "throat", "hum", "breath", "speech", "whisper", "breath",
            ];

            for _ in 0..num_distractors {
                let sound_type = sound_types.choose(&mut rng).unwrap();
                let human_noise = self.generate_human_sound(sound_type, None);

                let processed_noise = self.apply_audio_effects(&human_noise, "low");
                distractors.push(processed_noise);
            }

            for (idx, (_, char_pos)) in segments_with_positions.iter().enumerate() {
                if idx < segments_with_positions.len() - 1 {
                    let next_char_pos = segments_with_positions[idx + 1].1;
                    let gap = next_char_pos - *char_pos;

                    if gap > WAVE_SAMPLE_RATE as usize {
                        let num_in_gap = rng.gen_range(3..5);

                        for gap_idx in 0..num_in_gap {
                            let distractor = distractors.choose(&mut rng).unwrap();

                            let gap_segment_size = gap / (num_in_gap + 1);
                            let segment_start = *char_pos + gap_segment_size * (gap_idx + 1);

                            if segment_start + distractor.len() < next_char_pos {
                                let position = segment_start - gap_segment_size / 4
                                    + rng.gen_range(0..gap_segment_size / 2);

                                let volume_adjusted =
                                    self.change_volume(distractor, rng.gen_range(0.3..0.6));
                                combined_audio =
                                    self.mix_audio(&combined_audio, &volume_adjusted, position);
                            }
                        }
                    }
                }
            }
        }

        let audio_data = self.save_audio_to_bytes(&combined_audio, output_format)?;

        Ok(CaptchaChallenge {
            audio_data,
            characters: selected_chars,
            character_type: character_type.to_string(),
            language: language.to_string(),
            instruction: format!(
                "Listen to the sequence of {} characters and enter them in order.",
                count
            ),
            obfuscated: obfuscate,
            nonce,
            timestamp,
            indices_hash: indices_hash.into(),
            signature,
        })
    }

    pub fn validate_challenge(
        &self,
        selected_chars: &[String],
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

        let mut hasher = Hasher::new();
        hasher.update(nonce);
        hasher.update(selected_chars.join("").as_bytes());
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
}
