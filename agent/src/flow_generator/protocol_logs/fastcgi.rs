/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use public::bytes::read_u16_be;

use public::l7_protocol::L7Protocol;
use serde::Serialize;

use crate::common::flow::{L7PerfStats, PacketDirection};
use crate::common::l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface};
use crate::common::l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam};
use crate::flow_generator::protocol_logs::value_is_default;
use crate::flow_generator::{Error, Result};

use super::consts::{
    HTTP_STATUS_CLIENT_ERROR_MAX, HTTP_STATUS_CLIENT_ERROR_MIN, HTTP_STATUS_SERVER_ERROR_MAX,
    HTTP_STATUS_SERVER_ERROR_MIN,
};
use super::pb_adapter::TraceInfo;
use super::{check_http_method, parse_v1_headers, AppProtoHead, LogMessageType};
use super::{
    pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
    L7ResponseStatus,
};

const FCGI_RECORD_FIX_LEN: usize = 8;

const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_ABORT_REQUEST: u8 = 2;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_DATA: u8 = 8;
const FCGI_GET_VALUES: u8 = 9;
const FCGI_GET_VALUES_RESULT: u8 = 10;
const FCGI_UNKNOWN_TYPE: u8 = 11;
const FCGI_MAXTYPE: u8 = FCGI_UNKNOWN_TYPE;

#[derive(Serialize, Debug, Default, Clone)]
pub struct FastCgiInfo {
    version: u8,
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    request_id: u32,
    msg_type: LogMessageType,
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub method: String,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub path: String,
    #[serde(rename = "request_domain", skip_serializing_if = "value_is_default")]
    pub host: String,
    #[serde(rename = "user_agent", skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(rename = "server_addr", skip_serializing_if = "value_is_default")]
    pub server_addr: Option<String>,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    #[serde(rename = "response_status")]
    status: L7ResponseStatus,

    #[serde(rename = "request_length", skip_serializing_if = "Option::is_none")]
    pub req_content_length: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_content_length: Option<u32>,

    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_id: String,

    #[serde(skip)]
    rrt: u64,
}

impl L7ProtocolInfoInterface for FastCgiInfo {
    fn session_id(&self) -> Option<u32> {
        // Some(self.request_id)
        None
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::FastCgiInfo(info) = other {
            self.status = info.status;
            self.status_code = info.status_code;
        }

        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::FastCgi,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }
}

impl FastCgiInfo {
    // reference https://www.mit.edu/~yandros/doc/specs/fcgi-spec.html#S3.4
    fn fill_from_param(&mut self, param_payload: &[u8], direction: PacketDirection) -> Result<()> {
        let mut p = param_payload;
        while p.len() > 2 {
            let Ok((off,key_len,val_len)) = read_param_kv_len(p) else {
                break;
            };
            p = &p[off..];

            if p.len() < key_len + val_len {
                break;
            }

            let (key, val) = (&p[..key_len], &p[key_len..key_len + val_len]);
            self.on_param(key, val, direction)?;

            p = &p[(key_len + val_len)..]
        }

        Ok(())
    }

    fn on_param(&mut self, key: &[u8], val: &[u8], direction: PacketDirection) -> Result<()> {
        match key {
            b"REQUEST_METHOD" => self.method = String::from_utf8_lossy(val).to_string(),
            b"CONTENT_LENGTH" => {
                if val.len() != 0 {
                    let l = std::str::from_utf8(val)
                        .map_err(|_| Error::L7ProtocolUnknown)?
                        .parse::<u32>()
                        .map_err(|_| Error::L7ProtocolUnknown)?;
                    match direction {
                        PacketDirection::ClientToServer => self.req_content_length = Some(l),
                        PacketDirection::ServerToClient => self.resp_content_length = Some(l),
                    }
                }
            }
            b"SCRIPT_NAME" => {
                if self.path.is_empty() {
                    self.path = String::from_utf8_lossy(val).to_string()
                }
            }
            b"REQUEST_URI" => self.path = String::from_utf8_lossy(val).to_string(),
            b"SERVER_ADDR" => self.server_addr = Some(String::from_utf8_lossy(val).to_string()),
            b"HTTP_HOST" => self.host = String::from_utf8_lossy(val).to_string(),
            b"HTTP_USER_AGENT" => self.user_agent = Some(String::from_utf8_lossy(val).to_string()),
            b"HTTP_X_REQUEST_ID" => self.trace_id = String::from_utf8_lossy(val).to_string(),
            _ => {}
        }

        Ok(())
    }
}

impl From<FastCgiInfo> for L7ProtocolSendLog {
    fn from(f: FastCgiInfo) -> Self {
        Self {
            req: L7Request {
                req_type: f.method,
                domain: f.host,
                resource: f.path,
                endpoint: f.server_addr.unwrap_or_default(),
            },
            resp: L7Response {
                status: f.status,
                code: f.status_code,
                ..Default::default()
            },
            version: Some(f.version.to_string()),
            trace_info: if f.trace_id.is_empty() {
                None
            } else {
                Some(TraceInfo {
                    trace_id: Some(f.trace_id),
                    ..Default::default()
                })
            },
            ..Default::default()
        }
    }
}

// reference https://www.mit.edu/~yandros/doc/specs/fcgi-spec.html#S3.3
struct FastCgiRecord {
    version: u8,
    record_type: u8,
    request_id: u16,
    content_len: u16,
    padding_len: u8,
}

impl FastCgiRecord {
    fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < FCGI_RECORD_FIX_LEN {
            return Err(Error::L7ProtocolUnknown);
        }
        let r = Self {
            version: payload[0],
            record_type: payload[1],
            request_id: read_u16_be(&payload[2..]),
            content_len: read_u16_be(&payload[4..]),
            padding_len: payload[6],
        };
        if r.record_type > FCGI_MAXTYPE {
            return Err(Error::L7ProtocolUnknown);
        }
        Ok(r)
    }
}

#[derive(Debug, Serialize, Default)]
pub struct FastCgiLog {
    perf_stats: Option<L7PerfStats>,
}

impl FastCgiLog {
    fn set_status(&mut self, status_code: u16, info: &mut FastCgiInfo) {
        if status_code >= HTTP_STATUS_CLIENT_ERROR_MIN
            && status_code <= HTTP_STATUS_CLIENT_ERROR_MAX
        {
            // http客户端请求存在错误
            self.perf_stats.as_mut().map(|p| p.inc_req_err());
            info.status = L7ResponseStatus::ClientError;
        } else if status_code >= HTTP_STATUS_SERVER_ERROR_MIN
            && status_code <= HTTP_STATUS_SERVER_ERROR_MAX
        {
            self.perf_stats.as_mut().map(|p| p.inc_resp_err());
            info.status = L7ResponseStatus::ServerError;
        } else {
            info.status = L7ResponseStatus::Ok;
        }
    }
}

struct RecordIter<'a> {
    p: &'a [u8],
}

impl<'a> RecordIter<'a> {
    fn new(p: &'a [u8]) -> Self {
        Self { p: p }
    }
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = (FastCgiRecord, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let Ok(r) = FastCgiRecord::parse(self.p) else {
            return None;
        };

        let content_end = FCGI_RECORD_FIX_LEN + r.content_len as usize;
        let content = if content_end > self.p.len() {
            &self.p[FCGI_RECORD_FIX_LEN..]
        } else {
            &self.p[FCGI_RECORD_FIX_LEN..content_end]
        };
        let record_end = content_end + r.padding_len as usize;

        self.p = if record_end > self.p.len() {
            &self.p[self.p.len()..]
        } else {
            &self.p[record_end..]
        };

        Some((r, content))
    }
}

impl L7ProtocolParserInterface for FastCgiLog {
    fn check_payload(&mut self, payload: &[u8], _: &ParseParam) -> bool {
        let (mut req_check, mut method_check) = (false, false);
        for (r, p) in RecordIter::new(payload) {
            match r.record_type {
                FCGI_END_REQUEST | FCGI_STDOUT => return false,
                _ => {}
            }

            if !req_check && r.record_type == FCGI_BEGIN_REQUEST {
                req_check = true;
            };
            if r.record_type == FCGI_PARAMS {
                if let Ok(val) = get_param_val(p, "REQUEST_METHOD") {
                    method_check = check_http_method(
                        std::str::from_utf8(val)
                            .map_err(|_| Error::L7ProtocolUnknown)
                            .unwrap_or(""),
                    )
                    .is_ok();
                }
            }

            if req_check && method_check {
                break;
            }
        }

        if !(req_check && method_check) {
            get_param_val(payload, "REQUEST_METHOD").is_ok()
        } else {
            true
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() {
            self.perf_stats = Some(L7PerfStats::default())
        }

        let mut info = FastCgiInfo::default();

        let is_php = || {
            if let Some(e) = param.ebpf_param.as_ref() {
                e.process_kname.starts_with("php-fpm")
            } else {
                false
            }
        };
        match param.direction {
            PacketDirection::ClientToServer => {
                info.msg_type = LogMessageType::Request;
                if is_php() {
                    info.fill_from_param(payload, param.direction)?;
                } else {
                    for (record, record_payload) in RecordIter::new(payload) {
                        if record.record_type == FCGI_PARAMS {
                            info.request_id = record.request_id as u32;
                            if record.content_len > 0 {
                                info.fill_from_param(record_payload, param.direction)?;
                                break;
                            }
                        }
                    }
                }

                if info.method.is_empty() {
                    return Err(Error::L7ProtocolUnknown);
                }
                self.perf_stats.as_mut().map(|p| p.inc_req());
            }
            PacketDirection::ServerToClient => {
                info.msg_type = LogMessageType::Response;
                if is_php() {
                    let mut at_leaset_one_hdr = false;
                    for i in parse_v1_headers(payload) {
                        let Some(col_index) = i.find(':') else {
                            continue;
                        };

                        if col_index + 1 >= i.len() {
                            continue;
                        }
                        at_leaset_one_hdr = true;

                        let key = &i[..col_index];
                        let value = &i[col_index + 1..];

                        if key == "Status" {
                            if value.len() < 4 {
                                break;
                            }
                            if let Ok(status_code) = &value[1..4].parse::<u16>() {
                                info.status_code = Some(*status_code as i32);
                                self.set_status(*status_code, &mut info);
                            };
                            break;
                        }
                    }
                    if !at_leaset_one_hdr {
                        return Err(Error::L7ProtocolUnknown);
                    }
                    if info.status_code.is_none() {
                        info.status_code = Some(200);
                        self.set_status(200, &mut info);
                    }
                } else {
                    'l: for (record, record_payload) in RecordIter::new(payload) {
                        if record.record_type == FCGI_STDOUT {
                            info.request_id = record.request_id as u32;
                            for i in parse_v1_headers(record_payload) {
                                let Some(col_index) = i.find(':') else {
                                    continue;
                                };

                                if col_index + 1 >= i.len() {
                                    continue;
                                }

                                let key = &i[..col_index];
                                let value = &i[col_index + 1..];

                                if key == "Status" {
                                    if value.len() < 4 {
                                        break 'l;
                                    }
                                    if let Ok(status_code) = &value[1..4].parse::<u16>() {
                                        info.status_code = Some(*status_code as i32);
                                        self.set_status(*status_code, &mut info);
                                    };
                                    break 'l;
                                }
                            }

                            if info.status_code.is_none() {
                                info.status_code = Some(200);
                                self.set_status(200, &mut info);
                            }
                        }
                    }
                }

                if info.status_code.is_none() {
                    return Err(Error::L7ProtocolUnknown);
                }
                self.perf_stats.as_mut().map(|p| p.inc_resp());
            }
        }
        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
        Ok(L7ParseResult::Single(L7ProtocolInfo::FastCgiInfo(info)))
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::FastCgi
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

// return (offset, key_len, val_len)
fn read_param_kv_len(param_payload: &[u8]) -> Result<(usize, usize, usize)> {
    let mut p = param_payload;
    if p.len() < 2 {
        return Err(Error::L7ProtocolUnknown);
    }
    let mut off = 0;
    let (key_len, val_len);

    let key_len_b = p[0];
    if key_len_b >> 7 == 0 {
        key_len = key_len_b as usize;
        p = &p[1..];
        off += 1;
    } else {
        if p.len() < 4 {
            return Err(Error::L7ProtocolUnknown);
        }
        key_len = ((key_len_b as usize & 0x7f) << 24)
            + ((p[1] as usize) << 16)
            + ((p[2] as usize) << 8)
            + p[3] as usize;
        p = &p[4..];
        off += 4;
    }

    if p.is_empty() {
        return Err(Error::L7ProtocolUnknown);
    }

    let val_len_b = p[0];
    if val_len_b >> 7 == 0 {
        val_len = val_len_b as usize;
        off += 1;
    } else {
        if p.len() < 4 {
            return Err(Error::L7ProtocolUnknown);
        }
        val_len = ((val_len_b as usize & 0x7f) << 24)
            + ((p[1] as usize) << 16)
            + ((p[2] as usize) << 8)
            + p[3] as usize;
        off += 4;
    }

    return Ok((off, key_len, val_len));
}

fn get_param_val<'a>(param_payload: &'a [u8], key: &str) -> Result<&'a [u8]> {
    let mut p = param_payload;
    while p.len() > 2 {
        let Ok((off,key_len,val_len)) = read_param_kv_len(p) else {
            break;
        };
        p = &p[off..];

        if p.len() < key_len + val_len {
            return Err(Error::L7ProtocolUnknown);
        }

        let (k, val) = (&p[..key_len], &p[key_len..key_len + val_len]);
        if k == key.as_bytes() {
            return Ok(val);
        }

        p = &p[(key_len + val_len)..];
    }
    return Err(Error::L7ProtocolUnknown);
}
