/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <map>
#include <string>
#include <vector>

#include "mgos.hpp"
#include "mgos_bt.hpp"
#include "mgos_bt_gap.h"
#include "mgos_bt_gattc.h"
#include "mgos_rpc.h"

/*
 * Format for the output params for GATTC.Subscribe.
 */
#define GATTC_SUB_OUTPUT_FMT "{filename: %Q, max_file_size: %d}"

struct ScanResult {
  int rssi;
  std::string adv_data;
  std::string scan_rsp;
};
static std::map<mgos::BTAddr, ScanResult> s_scan_results;
static struct mg_rpc_request_info *s_scan_ri = nullptr;

static mgos::BTAddr s_connect_addr;
static struct mg_rpc_request_info *s_connect_ri = nullptr;

struct DiscoverResult {
  mgos::BTUUID svc;
  mgos::BTUUID chr;
  uint16_t handle;
  uint8_t prop;
};
static uint16_t s_discover_conn_id = 0xffff;
static struct mg_rpc_request_info *s_discover_ri = nullptr;
std::vector<DiscoverResult> s_discover_results;

static uint16_t s_read_conn_id = 0xffff;
static uint16_t s_read_handle = 0xffff;
static struct mg_rpc_request_info *s_read_ri = nullptr;

static uint16_t s_write_conn_id = 0xffff;
static uint16_t s_write_handle = 0xffff;
static struct mg_rpc_request_info *s_write_ri = nullptr;

static void gap_ev_handler(int ev, void *ev_data, void *userdata) {
  if (s_scan_ri == nullptr) return;
  switch (ev) {
    case MGOS_BT_GAP_EVENT_SCAN_RESULT: {
      const auto *r = (const struct mgos_bt_gap_scan_result *) ev_data;
      s_scan_results[r->addr] = {
          .rssi = r->rssi,
          .adv_data = std::string(r->adv_data.p, r->adv_data.len),
          .scan_rsp = std::string(r->scan_rsp.p, r->scan_rsp.len),
      };
      break;
    }
    case MGOS_BT_GAP_EVENT_SCAN_STOP: {
      std::string out;
      for (const auto &it : s_scan_results) {
        const ScanResult &r = it.second;
        if (out.size() > 0) mgos::JSONAppendStringf(&out, ", ");
        mgos::JSONAppendStringf(&out, "{addr: %Q, rssi: %d",
                                it.first.ToString(false).c_str(), r.rssi);
        struct mg_str name = mgos_bt_gap_parse_name(
            mg_mk_str_n(r.adv_data.data(), r.adv_data.size()));
        if (name.len > 0) {
          mgos::JSONAppendStringf(&out, ", name: %.*Q", (int) name.len, name.p);
        }
        if (r.adv_data.size() > 0) {
          mgos::JSONAppendStringf(&out, ", adv_data: %H",
                                  (int) r.adv_data.size(), r.adv_data.data());
        }
        if (r.scan_rsp.size() > 0) {
          mgos::JSONAppendStringf(&out, ", scan_rsp: %H",
                                  (int) r.scan_rsp.size(), r.scan_rsp.data());
        }
        mgos::JSONAppendStringf(&out, "}");
      }
      mg_rpc_send_responsef(s_scan_ri, "{results: [%s]}", out.c_str());
      s_scan_results.clear();
      s_scan_ri = nullptr;
      break;
    }
  }
  (void) userdata;
}

static void mgos_svc_gattc_scan(struct mg_rpc_request_info *ri, void *cb_arg,
                                struct mg_rpc_frame_info *fi,
                                struct mg_str args) {
  if (s_scan_ri != nullptr) {
    mg_rpc_send_errorf(ri, -1, "scan already in progress");
    return;
  }

  struct mgos_bt_gap_scan_opts opts = {};  // Use defaults
  json_scanf(args.p, args.len, ri->args_fmt, &opts.active, &opts.window_ms,
             &opts.interval_ms, &opts.duration_ms);

  s_scan_ri = ri;

  mgos_bt_gap_scan(&opts);

  (void) fi;
  (void) cb_arg;
  (void) args;
}

static void gattc_ev_handler(int ev, void *ev_data, void *userdata) {
  switch (ev) {
    case MGOS_BT_GATTC_EV_CONNECT: {
      if (s_connect_ri == nullptr) break;
      const auto *ca = (struct mgos_bt_gattc_connect_arg *) ev_data;
      if (s_connect_addr != ca->conn.addr) break;
      if (ca->ok) {
        mg_rpc_send_responsef(s_connect_ri, "{conn_id: %d}", ca->conn.conn_id);
      } else {
        mg_rpc_send_errorf(s_connect_ri, 500, "connect failed");
      }
      s_connect_ri = nullptr;
      break;
    }
    case MGOS_BT_GATTC_EV_DISCOVERY_RESULT: {
      if (s_discover_ri == nullptr) break;
      const auto *dr = (struct mgos_bt_gattc_discovery_result_arg *) ev_data;
      if (dr->conn.conn_id != s_discover_conn_id) break;
      s_discover_results.push_back({
          .svc = dr->svc,
          .chr = dr->chr,
          .handle = dr->handle,
          .prop = dr->prop,
      });
      break;
    }
    case MGOS_BT_GATTC_EV_DISCONNECT: {
      if (s_discover_ri != nullptr) {
        mg_rpc_send_errorf(s_discover_ri, 500, "disconnected");
        s_discover_results.clear();
        s_discover_ri = nullptr;
      }
      if (s_read_ri != nullptr) {
        mg_rpc_send_errorf(s_read_ri, 500, "disconnected");
        s_read_ri = nullptr;
      }
      break;
    }
    case MGOS_BT_GATTC_EV_DISCOVERY_DONE: {
      if (s_discover_ri == nullptr) break;
      const auto *dd = (struct mgos_bt_gattc_discovery_done_arg *) ev_data;
      if (dd->conn.conn_id != s_discover_conn_id) break;
      if (!dd->ok) {
        mg_rpc_send_errorf(s_discover_ri, 500, "discovery failed");
        s_discover_ri = nullptr;
        break;
      }
      std::string out;
      for (const DiscoverResult &r : s_discover_results) {
        if (out.size() > 0) mgos::JSONAppendStringf(&out, ", ");
        mgos::JSONAppendStringf(
            &out,
            "{svc_uuid: %Q, chr_uuid: %Q, handle: %u, props: \"%s%s%s%s%s\"}",
            r.svc.ToString().c_str(), r.chr.ToString().c_str(), r.handle,
            ((r.prop & MGOS_BT_GATT_PROP_READ) ? "R" : ""),
            ((r.prop & MGOS_BT_GATT_PROP_WRITE) ? "W" : ""),
            ((r.prop & MGOS_BT_GATT_PROP_WRITE_NR) ? "w" : ""),
            ((r.prop & MGOS_BT_GATT_PROP_NOTIFY) ? "N" : ""),
            ((r.prop & MGOS_BT_GATT_PROP_INDICATE) ? "I" : ""));
      }
      mg_rpc_send_responsef(s_discover_ri, "{results: [%s]}", out.c_str());
      s_discover_results.clear();
      s_discover_ri = nullptr;
      break;
    }
    case MGOS_BT_GATTC_EV_READ_RESULT: {
      if (s_read_ri == nullptr) break;
      const auto *rr = (struct mgos_bt_gattc_read_result_arg *) ev_data;
      if (rr->conn.conn_id != s_read_conn_id) break;
      if (rr->handle != s_read_handle) break;
      if (!rr->ok) {
        mg_rpc_send_errorf(s_read_ri, 500, "read failed");
        s_read_ri = nullptr;
        return;
      }
      bool is_printable = true;
      const struct mg_str v = rr->data;
      for (int i = 0; i < v.len; i++) {
        if (!isprint((int) v.p[i])) {
          is_printable = false;
          break;
        }
      }
      if (is_printable) {
        mg_rpc_send_responsef(s_read_ri, "{value: %.*Q}", (int) v.len, v.p);
      } else {
        mg_rpc_send_responsef(s_read_ri, "{value_hex: %H}", (int) v.len, v.p);
      }
      s_read_ri = nullptr;
      break;
    }
    case MGOS_BT_GATTC_EV_WRITE_RESULT: {
      if (s_write_ri == nullptr) break;
      const auto *wr = (struct mgos_bt_gattc_write_result_arg *) ev_data;
      if (wr->conn.conn_id != s_write_conn_id) break;
      if (wr->handle != s_write_handle) break;
      if (wr->ok) {
        mg_rpc_send_responsef(s_write_ri, nullptr);
      } else {
        mg_rpc_send_errorf(s_write_ri, 500, "write failed");
      }
      s_write_ri = nullptr;
      break;
    }
  }
  (void) userdata;
}

static void mgos_svc_gattc_connect(struct mg_rpc_request_info *ri, void *cb_arg,
                                   struct mg_rpc_frame_info *fi,
                                   struct mg_str args) {
  if (s_connect_ri != nullptr) {
    mg_rpc_send_errorf(ri, -1, "connect already in progress");
    return;
  }
  char *addr_str = nullptr;
  json_scanf(args.p, args.len, ri->args_fmt, &addr_str);
  mgos::ScopedCPtr o1(addr_str);

  if (addr_str == nullptr) {
    mg_rpc_send_errorf(ri, 400, "addr is required");
    return;
  }
  struct mgos_bt_addr addr;
  if (!mgos_bt_addr_from_str(mg_mk_str(addr_str), &addr)) {
    mg_rpc_send_errorf(ri, 400, "invalid addr");
    return;
  }
  if (mgos_bt_gattc_connect(&addr)) {
    s_connect_addr = addr;
    s_connect_ri = ri;
  } else {
    mg_rpc_send_errorf(ri, 500, "connect failed");
  }
  (void) fi;
  (void) cb_arg;
}

static void mgos_svc_gattc_discover(struct mg_rpc_request_info *ri,
                                    void *cb_arg, struct mg_rpc_frame_info *fi,
                                    struct mg_str args) {
  if (s_discover_ri != nullptr) {
    mg_rpc_send_errorf(ri, -1, "discovery already in progress");
    return;
  }

  int conn_id = -1;
  json_scanf(args.p, args.len, ri->args_fmt, &conn_id);
  if (conn_id < 0) {
    mg_rpc_send_errorf(ri, 400, "conn_id is required");
    return;
  }

  if (mgos_bt_gattc_discover(conn_id)) {
    s_discover_conn_id = conn_id;
    s_discover_ri = ri;
  } else {
    mg_rpc_send_errorf(ri, 500, "discovery failed");
  }

  (void) fi;
  (void) cb_arg;
}

static void mgos_svc_gattc_read(struct mg_rpc_request_info *ri, void *cb_arg,
                                struct mg_rpc_frame_info *fi,
                                struct mg_str args) {
  if (s_read_ri != nullptr) {
    mg_rpc_send_errorf(ri, -1, "read already in progress");
    return;
  }
  int conn_id = -1, handle = -1;
  json_scanf(args.p, args.len, ri->args_fmt, &conn_id, &handle);
  if (conn_id < 0 || handle < 0) {
    mg_rpc_send_errorf(ri, 400, "conn_id and handle are required");
    return;
  }
  if (mgos_bt_gattc_read(conn_id, handle)) {
    s_read_conn_id = conn_id;
    s_read_handle = handle;
    s_read_ri = ri;
  } else {
    mg_rpc_send_errorf(ri, 500, "read failed");
  }
}

static void mgos_svc_gattc_write(struct mg_rpc_request_info *ri, void *cb_arg,
                                 struct mg_rpc_frame_info *fi,
                                 struct mg_str args) {
  if (s_write_ri != nullptr) {
    mg_rpc_send_errorf(ri, -1, "write already in progress");
    return;
  }
  int conn_id = -1, handle = -1;
  int value_hex_len = -1;
  char *value = nullptr, *value_hex = nullptr;
  json_scanf(args.p, args.len, ri->args_fmt, &conn_id, &handle, &value,
             &value_hex_len, &value_hex);
  if (conn_id < 0 || handle < 0) {
    mg_rpc_send_errorf(ri, 400, "conn_id and handle are required");
    return;
  }
  mgos::ScopedCPtr o1(value), o2(value_hex);
  if ((value == nullptr && value_hex == nullptr) ||
      (value != nullptr && value_hex != nullptr)) {
    mg_rpc_send_errorf(ri, 400, "value or value_hex is required");
    return;
  }

  struct mg_str data =
      (value ? mg_mk_str(value) : mg_mk_str_n(value_hex, value_hex_len));

  if (mgos_bt_gattc_write(conn_id, handle, data, true /* resp_required */)) {
    s_write_conn_id = conn_id;
    s_write_handle = handle;
    s_write_ri = ri;
  } else {
    mg_rpc_send_errorf(ri, 500, "write failed");
  }
}

#if 0
struct mgos_svc_gattc_subscribe_ctx {
  struct mg_rpc_request_info *ri;

  /*
   * output settings: if `fp` is not NULL, then data is written there;
   * otherwise it goes to the console. `written` is the total number of bytes
   * written, and if `max_file_size` is greater than zero, then written never
   * goes above it.
   *
   * FIXME: At present, file is never closed. We have no way of knowing when
   * the connection is closed; when we do, this should be fixed.
   */
  FILE *fp;
  int max_file_size;
  int written;
};

static void mgos_svc_gattc_subscribe_cb(int conn_id, bool success,
                                        const struct mg_str value, void *arg) {
  struct mgos_svc_gattc_subscribe_ctx *ctx =
      (struct mgos_svc_gattc_subscribe_ctx *) arg;
  if (ctx->ri != nullptr) {
    if (success) {
      mg_rpc_send_responsef(ctx->ri, nullptr);
      ctx->ri = nullptr;
    } else {
      mg_rpc_send_errorf(ctx->ri, -1, "subscribe failed");
      ctx->ri = nullptr;
      free(ctx);
    }
  }
  if (!success) return;
  if (value.len > 0) {
    char buf[BT_UUID_STR_LEN];
    struct esp32_bt_connection bc;
    mgos_bt_gattc_get_conn_info(conn_id, &bc);
    if (ctx->fp == nullptr) {
      /* Output filename was not given, write data to log */
      LOG(LL_INFO,
          ("%d (%s): %.*s", conn_id, mgos_bt_addr_to_str(&bc.peer_addr, 0, buf),
           (int) value.len, value.p));
    } else {
      /* Write data to the given file */
      int len = value.len;
      if (ctx->max_file_size > 0 && len > (ctx->max_file_size - ctx->written)) {
        len = ctx->max_file_size - ctx->written;
      }
      if (len > 0) {
        fwrite(value.p, len, 1, ctx->fp);
        fflush(ctx->fp);
        ctx->written += len;
      }
    }
  }
}

static void mgos_svc_gattc_subscribe(struct mg_rpc_request_info *ri,
                                     void *cb_arg, struct mg_rpc_frame_info *fi,
                                     struct mg_str args) {
  int conn_id;
  struct mgos_bt_uuid svc_id, char_id;
  struct json_token unused_value_tok;
  int unused_value_hex_len;
  char *unused_value_hex = nullptr;
  char *filename = nullptr;

  if (!get_conn_svc_char_value(ri, args, &conn_id, &svc_id, &char_id,
                               &unused_value_tok, &unused_value_hex_len,
                               &unused_value_hex)) {
    goto clean;
  }

  struct mgos_svc_gattc_subscribe_ctx *ctx =
      (struct mgos_svc_gattc_subscribe_ctx *) calloc(1, sizeof(*ctx));
  ctx->ri = ri;

  json_scanf(args.p, args.len, "{output: " GATTC_SUB_OUTPUT_FMT "}", &filename,
             &ctx->max_file_size);
  if (filename != nullptr) {
    ctx->fp = fopen(filename, "wb");
    free(filename);
    filename = nullptr;
  }

  esp32_gattc_subscribe(conn_id, &svc_id, &char_id, mgos_svc_gattc_subscribe_cb,
                        ctx);

clean:
  (void) fi;
  (void) cb_arg;
}
#endif

static void mgos_svc_gattc_disconnect(struct mg_rpc_request_info *ri,
                                      void *cb_arg,
                                      struct mg_rpc_frame_info *fi,
                                      struct mg_str args) {
  int conn_id = -1;
  json_scanf(args.p, args.len, ri->args_fmt, &conn_id);
  if (conn_id < 0) {
    mg_rpc_send_errorf(ri, 400, "conn_id is required");
    return;
  }
  if (mgos_bt_gattc_disconnect(conn_id)) {
    mg_rpc_send_responsef(ri, nullptr);
  } else {
    mg_rpc_send_errorf(ri, 500, "disconnect failed");
  }

  (void) fi;
  (void) cb_arg;
}

extern "C" bool mgos_rpc_service_gattc_init(void) {
  mgos_event_add_group_handler(MGOS_BT_GAP_EVENT_BASE, gap_ev_handler, nullptr);
  mgos_event_add_group_handler(MGOS_BT_GATTC_EV_BASE, gattc_ev_handler,
                               nullptr);
  struct mg_rpc *rpc = mgos_rpc_get_global();
  mg_rpc_add_handler(
      rpc, "GATTC.Scan",
      "{active: %B, window_ms: %d, interval_ms: %d, duration_ms: %d}",
      mgos_svc_gattc_scan, nullptr);
  mg_rpc_add_handler(rpc, "GATTC.Connect", "{addr: %Q}", mgos_svc_gattc_connect,
                     nullptr);
  mg_rpc_add_handler(rpc, "GATTC.Discover", "{conn_id: %u}",
                     mgos_svc_gattc_discover, nullptr);
  mg_rpc_add_handler(rpc, "GATTC.Read", "{conn_id: %u, handle: %u}",
                     mgos_svc_gattc_read, nullptr);
  mg_rpc_add_handler(rpc, "GATTC.Write",
                     "{conn_id: %d, handle: %u, value: %Q, value_hex: %H}",
                     mgos_svc_gattc_write, nullptr);
#if 0
  mg_rpc_add_handler(rpc, "GATTC.Subscribe",
                     "{conn_id: %d, svc_uuid: %Q, char_uuid: %Q, "
                     "output: " GATTC_SUB_OUTPUT_FMT "}",
                     mgos_svc_gattc_subscribe, nullptr);
#endif
  mg_rpc_add_handler(rpc, "GATTC.Disconnect", "{conn_id: %u}",
                     mgos_svc_gattc_disconnect, nullptr);
  return true;
}
