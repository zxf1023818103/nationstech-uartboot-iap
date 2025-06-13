#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <termios.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/select.h>

#define CMD_GET_INF 0x10
#define CMD_GET_RNG 0x20
#define CMD_KEY_UPDATE 0x21
#define CMD_FLASH_ERASE 0x30
#define CMD_FLASH_DWNLD 0x31
#define CMD_DATA_CRC_CHECK 0x32
#define CMD_OPT_RW 0x40
#define CMD_USERX_OP 0x41
#define CMD_SYS_RESET 0x50

#pragma pack(1)

struct resp_get_inf {
    uint8_t model_id;
    uint8_t bootcmd_version_major : 4;
    uint8_t bootcmd_version_minor : 4;
    uint8_t boot_version_minor : 4;
    uint8_t boot_version_major : 4;
    uint8_t ucid[16];
    uint8_t chip_id[12];
    uint8_t dbgmcu_idcode[4];
    uint8_t reserved[16];
};

struct resp_key_rng {
    uint8_t rng[16];
};

struct resp_opt_rw {
    uint8_t RDP, nRDP, USER, nUSER, Data0, nData0, Data1, nData1, WRP0, nWRP0, WRP1, nWRP1, WRP2, nWRP2, WRP3, nWRP3, RDP2, nRDP2, Reserved, nReserved;
};

struct resp_userx_op {
    uint8_t partition_id;
    uint8_t partition_16k_bytes;
    uint8_t id_configured;
    uint8_t authentication_required : 4;
    uint8_t encrypted : 4;
};

#pragma pack()

enum parser_state {
    STATE_HEADER1 = 0,
    STATE_HEADER2,
    STATE_CMD_H,
    STATE_CMD_L,
    STATE_DATA_LEN_L,
    STATE_DATA_LEN_H,
    STATE_DATA,
    STATE_CR1,
    STATE_CR2,
    STATE_CHECKSUM,
};

enum parser_ret {
    PARSER_OK = 0,
    PARSER_MORE_DATA_REQUIRED = 1,
    PARSER_CHECKSUM_ERROR = -1,
    PARSER_UNEXPECTED_STATE = -2,
    PARSER_UART_ERROR = -3,
    PARSER_BUFFER_OVERFLOW = -4,
    PARSER_RESPONSE_ERROR = -5,
};

typedef int (*uart_send_func_t)(void *args, const uint8_t *data, int len);
typedef int (*uart_recv_func_t)(void *args, uint32_t uart_idle_timeout_sec);
typedef int (*firmeware_recv_func_t)(void *args, uint8_t *data, int len, uint32_t firmware_recv_timeout_sec);

static const char *parser_state_to_string(enum parser_state state)
{
    switch (state) {
        case STATE_HEADER1: return "STATE_HEADER1";
        case STATE_HEADER2: return "STATE_HEADER2";
        case STATE_CMD_H: return "STATE_CMD_H";
        case STATE_CMD_L: return "STATE_CMD_L";
        case STATE_DATA_LEN_L: return "STATE_DATA_LEN_L";
        case STATE_DATA_LEN_H: return "STATE_DATA_LEN_H";
        case STATE_DATA: return "STATE_DATA";
        case STATE_CR1: return "STATE_CR1";
        case STATE_CR2: return "STATE_CR2";
        case STATE_CHECKSUM: return "STATE_CHECKSUM";
        default: return "UNKNOWN_STATE";
    }
}

static const char *parser_ret_to_string(int ret)
{
    switch (ret) {
        case PARSER_OK: return "PARSER_OK";
        case PARSER_MORE_DATA_REQUIRED: return "PARSER_MORE_DATA_REQUIRED";
        case PARSER_CHECKSUM_ERROR: return "PARSER_CHECKSUM_ERROR";
        case PARSER_UNEXPECTED_STATE: return "PARSER_UNEXPECTED_STATE";
        case PARSER_UART_ERROR: return "PARSER_UART_ERROR";
        case PARSER_BUFFER_OVERFLOW: return "PARSER_BUFFER_OVERFLOW";
        case PARSER_RESPONSE_ERROR: return "PARSER_RESPONSE_ERROR";
        default: return "UNKNOWN_RET";
    }
}

static enum parser_ret parse_one_byte(uart_recv_func_t uart_recv, void *args, uint32_t uart_idle_timeout_sec, uint8_t *cmd_h, uint8_t *cmd_l, uint8_t *data, uint16_t *data_len, uint32_t max_data_len, uint8_t *cr1, uint8_t *cr2,
                        enum parser_state *state, uint16_t *current_data_len, uint8_t *current_checksum, uint8_t *checksum)
{
    int c = uart_recv(args, uart_idle_timeout_sec);
    if (c < 0 || c > 255) {
        return PARSER_UART_ERROR; // Error or no data received
    }

    uint8_t input = (uint8_t)c;
    enum parser_ret ret = PARSER_MORE_DATA_REQUIRED;
    enum parser_state prev_state = *state;
    switch (prev_state) {
        case STATE_HEADER1: {
            *current_checksum = *checksum = 0;
            *current_data_len = *data_len = 0;
            *cmd_h = *cmd_l = 0;
            *cr1 = *cr2 = 0;
            if (input == 0xAA) {
                *state = STATE_HEADER2;
                *current_checksum ^= input;
            }
            break;
        }
        case STATE_HEADER2: {
            if (input == 0x55) {
                *state = STATE_CMD_H;
                *current_checksum ^= input;
            } else {
                *state = STATE_HEADER1;
            }
            break;
        }
        case STATE_CMD_H: {
            *cmd_h = input;
            *current_checksum ^= input;
            *state = STATE_CMD_L;
            break;
        }
        case STATE_CMD_L: {
            *cmd_l = input;
            *current_checksum ^= input;
            *state = STATE_DATA_LEN_L;
            break;
        }
        case STATE_DATA_LEN_L: {
            *data_len = input;
            *current_checksum ^= input;
            *state = STATE_DATA_LEN_H;
            break;
        }
        case STATE_DATA_LEN_H: {
            uint16_t data_len_h = input;
            data_len_h <<= 8;
            *data_len |= data_len_h;
            *current_checksum ^= input;
            if (*data_len > 0) {
                *state = STATE_DATA;
            } else {
                *state = STATE_CR1;
            }
            break;
        }
        case STATE_DATA: {
            if (*current_data_len < max_data_len) {
                *current_checksum ^= input;
                data[(*current_data_len)++] = input;
                if (*current_data_len == *data_len) {
                    *state = STATE_CR1;
                }
            }
            else {
                ret = PARSER_BUFFER_OVERFLOW;
            }
            break;
        }
        case STATE_CR1: {
            *current_checksum ^= input;
            *state = STATE_CR2;
            *cr1 = input;
            break;
        }
        case STATE_CR2: {
            *current_checksum ^= input;
            *state = STATE_CHECKSUM;
            *cr2 = input;
            break;
        }
        case STATE_CHECKSUM: {
            *checksum = input;
            if (*checksum == *current_checksum) {
                *state = STATE_HEADER1; // Reset state for next command
                ret = PARSER_OK; // Successfully parsed a complete command
            } else {
                *state = STATE_HEADER1; // Reset state on checksum error
                ret = PARSER_CHECKSUM_ERROR; // Checksum error
            }
            break;
        }
        default: {
            *state = STATE_HEADER1; // Reset state on unexpected input
            ret = PARSER_UNEXPECTED_STATE; // Unexpected state
            break;
        }
    }

    // enum parser_state next_state = *state;
    // printf("%s() input=0x%02X prev_state=%s next_state=%s cmd_h=0x%02X cmd_l=0x%02X cr1=0x%02X cr2=0x%02X current_data_len=%d data_len=%d max_data_len=%d current_checksum=0x%02X checksum=0x%02X ret=%s\n",
    //        __func__, input, parser_state_to_string(prev_state), parser_state_to_string(next_state), *cmd_h, *cmd_l, *cr1, *cr2, *current_data_len, *data_len, max_data_len, *current_checksum, *checksum, parser_ret_to_string(ret));

    return ret;
}

static enum parser_ret recv_next_packet(uart_recv_func_t uart_recv, void *args, uint32_t uart_idle_timeout_sec, uint8_t *cmd_h, uint8_t *cmd_l, uint8_t *data, uint16_t *data_len, uint32_t max_data_len, uint8_t *cr1, uint8_t *cr2)
{
    enum parser_state state = STATE_HEADER1;
    uint16_t current_data_len = 0;
    uint8_t current_checksum = 0;
    uint8_t checksum = 0;

    while (1) {
        enum parser_ret parse_ret = parse_one_byte(uart_recv, args, uart_idle_timeout_sec, cmd_h, cmd_l, data, data_len, max_data_len, cr1, cr2, &state, &current_data_len, &current_checksum, &checksum);
        if (parse_ret != PARSER_MORE_DATA_REQUIRED) {
            return parse_ret;
        }
    }
}

static int send_cmd(uart_send_func_t uart_send, void *args, uint8_t cmd_h, uint8_t cmd_l, uint8_t *par_4bytes,
                     const uint8_t *data, uint16_t data_len)
{
    uint8_t data_len_l = data_len & 0xFF;
    uint8_t data_len_h = (data_len >> 8) & 0xFF;
    uint8_t buf[10] = {
        0xAA, 0x55, cmd_h, cmd_l, data_len_l, data_len_h,
    };

    if (par_4bytes) {
        memcpy(buf + 6, par_4bytes, 4);
    }
    
    uint8_t checksum = 0;
    for (int i = 0; i < sizeof(buf); i++) {
        checksum ^= buf[i];
    }
    for (int i = 0; i < data_len; i++) {
        checksum ^= data[i];
    }

    int nbytes = 0;
    int ret = uart_send(args, buf, sizeof(buf));
    if (ret == sizeof(buf)) {
        nbytes += ret;
        ret = uart_send(args, data, data_len);
        if (ret == data_len) {
            nbytes += ret;
            ret = uart_send(args, &checksum, 1);
            if (ret == 1) {
                nbytes += ret;
                return nbytes;
            }
        }
    }

    return -1;
}

static enum parser_ret send_cmd_get_resp(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec, uint8_t cmd_h, uint8_t cmd_l, uint8_t *par_4bytes, const uint8_t *data, uint16_t data_len, uint8_t *resp, uint32_t resp_len)
{
    enum parser_ret ret;
    if (send_cmd(uart_send, args, cmd_h, cmd_l, par_4bytes, data, data_len) > 0) {
        uint8_t recv_cmd_h = 0, recv_cmd_l = 0, cr1 = 0, cr2 = 0;
        uint16_t recv_data_len = 0;
        ret = recv_next_packet(uart_recv, args, uart_idle_timeout_sec, &recv_cmd_h, &recv_cmd_l, resp, &recv_data_len, resp_len, &cr1, &cr2);
        if (ret == PARSER_OK && recv_cmd_h == cmd_h && recv_cmd_l == cmd_l && recv_data_len == resp_len) {
            if (cr1 == 0xA0 && cr2 == 0x00) {
                ret = PARSER_OK;
            }
            else {
                printf("%s(): Unexpected response: cmd_h=0x%02X, cmd_l=0x%02X, cr1=0x%02X, cr2=0x%02X\n", __func__, cmd_h, cmd_l, cr1, cr2);
                ret = PARSER_RESPONSE_ERROR;
            }
        }
    }
    else {
        ret = PARSER_UART_ERROR;
    }

    return ret;
}            

static enum parser_ret get_inf(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec)
{
    struct resp_get_inf resp_inf = { 0 };
    enum parser_ret ret = send_cmd_get_resp(uart_recv, uart_send, args, uart_idle_timeout_sec, CMD_GET_INF, 0, NULL, NULL, 0, (uint8_t*)&resp_inf, sizeof(struct resp_get_inf));
    if (ret == PARSER_OK) {
        printf("Device Model ID: %d\n", resp_inf.model_id);
        printf("Boot Command Version: %d.%d\n", resp_inf.bootcmd_version_major, resp_inf.bootcmd_version_minor);
        printf("Boot Version: %d.%d\n", resp_inf.boot_version_major, resp_inf.boot_version_minor);
        printf("UCID: ");
        for (int i = 0; i < sizeof(resp_inf.ucid); i++) {
            printf("%02X", resp_inf.ucid[i]);
        }
        printf("\n");
        printf("Chip ID: ");
        for (int i = 0; i < sizeof(resp_inf.chip_id); i++) {
            printf("%02X", resp_inf.chip_id[i]);
        }
        printf("\n");
        printf("MCU Device ID Code: ");
        for (int i = 0; i < sizeof(resp_inf.dbgmcu_idcode); i++) {
            printf("%02X", resp_inf.dbgmcu_idcode[i]);
        }
        printf("\n");
    }
    
    return ret;
}

static enum parser_ret get_userx_op(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec, uint8_t partition_id)
{
    struct resp_userx_op resp_userx_op = { 0 };
    uint8_t par[4] = { partition_id };
    enum parser_ret ret = send_cmd_get_resp(uart_recv, uart_send, args, uart_idle_timeout_sec, CMD_USERX_OP, 0, par, NULL, 0, (uint8_t*)&resp_userx_op, sizeof(struct resp_userx_op));
    if (ret == PARSER_OK) {
        printf("Partition ID: USER%d\n", resp_userx_op.partition_id + 1);
        if (resp_userx_op.partition_16k_bytes) {
            printf("Partition Size: %dk bytes\n", resp_userx_op.partition_16k_bytes * 16);
        }
        else {
            printf("Partition Size: Not configured\n");
        }
        printf("ID Configured: %s\n", !resp_userx_op.id_configured ? "Yes" : "No");
        printf("Authentication Required: %s\n", resp_userx_op.authentication_required ? "Yes" : "No");
        printf("Encrypted: %s\n", resp_userx_op.encrypted ? "Yes" : "No");
    }

    return ret;
}

static enum parser_ret get_opt_rw(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec)
{
    uint8_t data[20] = { 0 };
    struct resp_opt_rw resp_opt_rw = { 0 };
    enum parser_ret ret = send_cmd_get_resp(uart_recv, uart_send, args, uart_idle_timeout_sec, CMD_OPT_RW, 0, NULL, data, sizeof data, (uint8_t*)&resp_opt_rw, sizeof(struct resp_opt_rw));
    if (ret == PARSER_OK) {
        printf("RDP: %d\n", resp_opt_rw.RDP);
        printf("nRDP: %d\n", resp_opt_rw.nRDP);
        printf("USER: %d\n", resp_opt_rw.USER);
        printf("nUSER: %d\n", resp_opt_rw.nUSER);
        printf("Data0: %d\n", resp_opt_rw.Data0);
        printf("nData0: %d\n", resp_opt_rw.nData0);
        printf("Data1: %d\n", resp_opt_rw.Data1);
        printf("nData1: %d\n", resp_opt_rw.nData1);
        printf("WRP0: %d\n", resp_opt_rw.WRP0);
        printf("nWRP0: %d\n", resp_opt_rw.nWRP0);
        printf("WRP1: %d\n", resp_opt_rw.WRP1);
        printf("nWRP1: %d\n", resp_opt_rw.nWRP1);
        printf("WRP2: %d\n", resp_opt_rw.WRP2);
        printf("nWRP2: %d\n", resp_opt_rw.nWRP2);
        printf("WRP3: %d\n", resp_opt_rw.WRP3);
        printf("nWRP3: %d\n", resp_opt_rw.nWRP3);
        printf("RDP2: %d\n", resp_opt_rw.RDP2);
        printf("nRDP2: %d\n", resp_opt_rw.nRDP2);
    }

    return ret;
}

static enum parser_ret do_flash_erase(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec, uint8_t partition_id, uint8_t *key, uint16_t start_page, uint16_t page_size)
{
    uint8_t start_page_l = start_page & 0xFF;
    uint8_t start_page_h = (start_page >> 8) & 0xFF;
    uint8_t page_size_l = page_size & 0xFF;
    uint8_t page_size_h = (page_size >> 8) & 0xFF;
    uint8_t par[4] = {start_page_l, start_page_h, page_size_l, page_size_h};
    enum parser_ret ret = send_cmd_get_resp(uart_recv, uart_send, args, uart_idle_timeout_sec, CMD_FLASH_ERASE, partition_id, par, key, key ? 16 : 0, NULL, 0);
    if (ret == PARSER_OK) {
        printf("Flash erased 0x%08X - 0x%08X\n", 0x08000000 + (start_page * 0x800), 0x08000000 + ((start_page + page_size) * 0x800));
    }

    return ret;
}

static enum parser_ret do_flash_download(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec, uint8_t partition_id, uint32_t flash_addr, uint8_t *data, uint16_t data_len)
{
    uint8_t par[4];
    par[0] = flash_addr & 0xFF;
    par[1] = (flash_addr >> 8) & 0xFF;
    par[2] = (flash_addr >> 16) & 0xFF;
    par[3] = (flash_addr >> 24) & 0xFF;
    enum parser_ret ret = send_cmd_get_resp(uart_recv, uart_send, args, uart_idle_timeout_sec, CMD_FLASH_DWNLD, partition_id, par, data, data_len, NULL, 0);
    if (ret == PARSER_OK) {
        printf("Flash downloaded %d bytes to 0x%08X\n", data_len - 16 - 4, flash_addr);
    }

    return ret;
}

static enum parser_ret do_data_crc_check(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec, uint8_t partition_id, uint8_t *key, uint32_t start_addr, uint32_t size, uint32_t crc)
{
    uint8_t data[16 + 4 + 4] = { 0 };
    if (key) {
        memcpy(data, key, 16);
    }
    data[16] = start_addr & 0xFF;
    data[17] = (start_addr >> 8) & 0xFF;
    data[18] = (start_addr >> 16) & 0xFF;
    data[19] = (start_addr >> 24) & 0xFF;
    data[20] = size & 0xFF;
    data[21] = (size >> 8) & 0xFF;
    data[22] = (size >> 16) & 0xFF;
    data[23] = (size >> 24) & 0xFF;

    uint8_t crc_bytes[4];
    crc_bytes[0] = crc & 0xFF;
    crc_bytes[1] = (crc >> 8) & 0xFF;
    crc_bytes[2] = (crc >> 16) & 0xFF;
    crc_bytes[3] = (crc >> 24) & 0xFF;
    enum parser_ret ret = send_cmd_get_resp(uart_recv, uart_send, args, uart_idle_timeout_sec, CMD_DATA_CRC_CHECK, partition_id, crc_bytes, data, sizeof data, NULL, 0);
    if (ret == PARSER_OK) {
        printf("Checksum OK.\n");
    }

    return ret;
}

static enum parser_ret do_sys_reset(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec)
{
    enum parser_ret ret = send_cmd_get_resp(uart_recv, uart_send, args, uart_idle_timeout_sec, CMD_SYS_RESET, 0, NULL, NULL, 0, NULL, 0);
    if (ret == PARSER_OK) {
        printf("System reset command sent successfully.\n");
        // Note: The device will reset, so we won't receive any further responses.
    }

    return ret;
}

uint32_t ns_crc32(uint32_t initial_crc, const uint8_t *data, uint32_t len)
{
    const uint32_t polynom = 0x04c11db7; // Polynomial for CRC-32
    uint32_t crc = initial_crc; // Initialize CRC with the initial value

    for (uint32_t i = 0; i < len; i += 4) {
        uint32_t little_endian = 0;
        if (i + 3 < len) {
            little_endian = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24));
        } else {
            for (uint32_t j = 0; i + j < len; j++) {
                little_endian |= (data[i + j] << (j * 8));
            }
        }

        uint32_t xbit = xbit = 1 << 31;
        for (int bit = 0; bit < 32; bit++) {
            if (crc & 0x80000000) {
                crc <<= 1;
                crc ^= polynom;
            }
            else {
                crc <<= 1;
            }

            if (little_endian & xbit) {
                crc ^= polynom;
            }

            xbit >>= 1;
        }
    }

    return crc;
}

static int do_firmware_download(uart_recv_func_t uart_recv, uart_send_func_t uart_send, firmeware_recv_func_t firmeware_recv, void *uart_args, uint32_t uart_idle_timeout_sec, void *firmeware_recv_args, uint32_t firmware_recv_timeout_sec, uint8_t partition_id, uint8_t *key, uint32_t flash_addr)
{
    int ret = 0;
    uint8_t cmd_data[128 + 16 + 4];
    if (key) {
        memcpy(cmd_data, key, 16);
    }

    uint32_t start_flash_addr = flash_addr;
    uint32_t firmware_bytes = 0, writen_bytes = 0;
    uint32_t firmware_crc = 0xffffffff;
    for (;;) {
        memset(cmd_data, 0xff, sizeof cmd_data);
        int nbytesrecv = firmeware_recv(firmeware_recv_args, cmd_data + 16, 128, firmware_recv_timeout_sec);
        if (nbytesrecv > 0) {
            firmware_bytes += nbytesrecv;
            uint16_t data_len = nbytesrecv + 16;
            int last_packet = 0;
            if (data_len % 16) {
                data_len += 16 - (data_len % 16); // Align to 16 bytes
                last_packet = 1;
            }
            writen_bytes += data_len - 16;
            uint32_t crc = ns_crc32(0xffffffff, cmd_data + 16, data_len - 16);
            firmware_crc = ns_crc32(firmware_crc, cmd_data + 16, data_len - 16);
            
            uint8_t crc_bytes[4];
            crc_bytes[0] = crc & 0xFF;
            crc_bytes[1] = (crc >> 8) & 0xFF;
            crc_bytes[2] = (crc >> 16) & 0xFF;
            crc_bytes[3] = (crc >> 24) & 0xFF;
            memcpy(cmd_data + data_len, crc_bytes, 4); // Append CRC
            
            ret = do_flash_download(uart_recv, uart_send, uart_args, uart_idle_timeout_sec, partition_id, flash_addr, cmd_data, data_len + 4);
            if (ret >= 0 && !last_packet) {
                flash_addr += nbytesrecv;
            }
            else {
                break;
            }
        }
        else if (nbytesrecv == 0) { // EOF
            ret = writen_bytes;
            break;
        }
        else {
            ret = -1;
            break;
        }
    }

    uint32_t crc32_bytes = writen_bytes;
    if (crc32_bytes < 2048) {
        crc32_bytes = 2048;
        for (uint32_t i = 0; i < 2048 - writen_bytes; i++) {
            uint8_t fill_byte = 0xff; // Fill with 0xff
            firmware_crc = ns_crc32(firmware_crc, &fill_byte, 1);
        }
    }

    if (ret >= 0) {
        if ((ret = do_data_crc_check(uart_recv, uart_send, uart_args, uart_idle_timeout_sec, partition_id, key, start_flash_addr, writen_bytes, firmware_crc)) == 0) {
            printf("Firmware download completed, total size: %d bytes, writen %d bytes, CRC32 calculated %d bytes, CRC32 value: 0x%08X.\n", firmware_bytes, writen_bytes, crc32_bytes, firmware_crc);
        }
    }
    else {
        printf("Error reading firmware data.\n");
    }

    return ret;
}

static enum parser_ret do_boot_flag_write(uart_recv_func_t uart_recv, uart_send_func_t uart_send, void *args, uint32_t uart_idle_timeout_sec, uint8_t partition_id, uint8_t *key, uint32_t boot_flag_addr, uint32_t boot_flag)
{
    uint8_t cmd_data[16 + 16 + 4];
    memset(cmd_data, 0xff, sizeof cmd_data);
    if (key) {
        memcpy(cmd_data, key, 16);
    }
    memcpy(cmd_data + 16, &boot_flag, sizeof boot_flag);

    uint32_t crc = ns_crc32(0xffffffff, cmd_data + 16, 16);

    uint8_t crc_bytes[4];
    crc_bytes[0] = crc & 0xFF;
    crc_bytes[1] = (crc >> 8) & 0xFF;
    crc_bytes[2] = (crc >> 16) & 0xFF;
    crc_bytes[3] = (crc >> 24) & 0xFF;
    memcpy(cmd_data + 32, crc_bytes, 4); // Append CRC

    enum parser_ret ret = do_flash_download(uart_recv, uart_send, args, uart_idle_timeout_sec, partition_id, boot_flag_addr, cmd_data, sizeof cmd_data);
    if (ret == PARSER_OK) {
        printf("Write boot flag 0x%08X.\n", boot_flag);
    }
    else {
        printf("Failed to write boot flag 0x%08X.\n", boot_flag);
    }

    return ret;
}

static int flash_download(uart_recv_func_t uart_recv, uart_send_func_t uart_send, firmeware_recv_func_t firmeware_recv, void *uart_args, uint32_t uart_idle_timeout_sec, void *firmeware_recv_args, uint32_t firmware_recv_timeout_sec, uint8_t partition_id, uint8_t *key, uint32_t flash_addr, uint32_t boot_flag_addr)
{
    int ret = 0;
    if ((ret = get_inf(uart_recv, uart_send, uart_args, uart_idle_timeout_sec)) == PARSER_OK) {
        if ((ret = get_userx_op(uart_recv, uart_send, uart_args, uart_idle_timeout_sec, 0)) == PARSER_OK) {
            if ((ret = do_flash_erase(uart_recv, uart_send, uart_args, uart_idle_timeout_sec, 0, NULL, 5, 256 - 5)) == PARSER_OK) {
                if ((ret = do_firmware_download(uart_recv, uart_send, firmeware_recv, uart_args, uart_idle_timeout_sec, firmeware_recv_args, firmware_recv_timeout_sec, partition_id, key, flash_addr)) == 0) {
                    if ((ret = do_boot_flag_write(uart_recv, uart_send, uart_args, uart_idle_timeout_sec, partition_id, key, boot_flag_addr, 0x12345678)) == PARSER_OK) {
                        ret = do_sys_reset(uart_recv, uart_send, uart_args, uart_idle_timeout_sec);
                    }
                }
            }
        }
    }
    return ret;
}

static int my_uart_send(void *args, const uint8_t *data, int len)
{
    int ret = -1;
    int fd = (int)args;

    int sent = 0;
    while (sent < len) {
        struct timeval tm = {
            .tv_sec = 1,
        };
        fd_set write_fds = { 0 }, except_fds = { 0 };
        FD_SET(fd, &write_fds);
        FD_SET(fd, &except_fds);
        int nfds = select(fd + 1, NULL, &write_fds, &except_fds, &tm);
        if (nfds > 0) {
            if (FD_ISSET(fd, &write_fds)) {
                ret = write(fd, data + sent, len - sent);
                if (ret >= 0) {
                    sent += ret;
                    continue;
                }
            }
            perror(__func__);
            return ret;
        }
    }
    return sent;
}

static int my_uart_recv(void *args, uint32_t uart_idle_timeout_sec)
{
    int ret = -1;
    int fd = (int)args;

    struct timeval tm = {
        .tv_sec = uart_idle_timeout_sec,
    };

    fd_set read_fds = { 0 };
    FD_SET(fd, &read_fds);
    int nfds = select(fd + 1, &read_fds, NULL, NULL, &tm);
    if (nfds > 0 && FD_ISSET(fd, &read_fds)) {
        uint8_t input;
        ret = read(fd, &input, sizeof input);
        if (ret == 1) {
            ret = input;
        }
    }
    else {
        printf("%s(): recv timeout %u.\n", __func__, uart_idle_timeout_sec);
    }
    return ret;
}

static int my_firmware_recv(void *args, uint8_t *data, int len, uint32_t firmware_recv_timeout_sec)
{
    int ret = -1;
    int fd = (int)args;

    struct timeval tm = {
        .tv_sec = firmware_recv_timeout_sec,
    };

    fd_set read_fds = { 0 };
    FD_SET(fd, &read_fds);
    int nfds = select(fd + 1, &read_fds, NULL, NULL, &tm);
    if (nfds > 0 && FD_ISSET(fd, &read_fds)) {
        ret = read(fd, data, len);
        // printf("%s recv=%d received=%d\n", __func__, len, ret);
    }
    else {
        printf("%s(): recv timeout %u.\n", __func__, firmware_recv_timeout_sec);
    }
    return ret;
}

static void print_version(void)
{
    printf("%s version %s\n", GIT_REPO_NAME, VERSION);
}

static void print_usage(void)
{
    printf("Usage: %s <-d device -f file>\n", GIT_REPO_NAME);
    printf("%s\n", "  -d <device>    Specify serial port. eg: /dev/ttyS0");
    printf("%s\n", "  -f <file>      Specify firmware .bin file path. eg: helloworld.bin");
    printf("\n");
    printf("%s\n", "For bug reporting instructions, please see:");
    printf("<%s>\n", HOMEPAGE);
}

int main(int argc, char *argv[])
{
    const char *shortopts = "vhd:f:";

    int ch, help_flag = 0, version_flag = 0;
    char *device = NULL, *file = NULL;
    while ((ch = getopt(argc, argv, shortopts)) != -1) {
        switch (ch) {
            case 'v':
                version_flag = 1;
                break;
            case 'h':
                help_flag = 1;
                break;
            case 'd':
                device = optarg;
                break;
            case 'f':
                file = optarg;
                break;
        }
    }

    if (help_flag) {
        print_usage();
        return 0;
    }
    else if (version_flag) {
        print_version();
        return 0;
    }
    else if (!device || !file) {
        print_usage();
        return -1;
    }

    int file_fd;
    if (strcmp(file, "-") == 0) {
        file_fd = STDIN_FILENO;
    }
    else {
        file_fd = open(file, O_RDONLY);
    }

    int ret = -1;
    if (file_fd >= 0) {
        ret = fcntl(file_fd, F_SETFD, O_NONBLOCK);
        if (ret >= 0) {
            int device_fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
            if (device_fd >= 0) {
                struct termios termios;
                if (tcgetattr(device_fd, &termios) == 0) {
                    cfsetispeed(&termios, B9600);
                    cfsetospeed(&termios, B9600);

                    termios.c_cflag |= CLOCAL | CREAD;
                    termios.c_cflag &= CSIZE;
                    termios.c_cflag |= CS8;
                    termios.c_cflag &= ~PARENB;
                    termios.c_cflag &= ~CSTOPB;

                    termios.c_oflag = termios.c_lflag = termios.c_iflag = 0;

                    if (tcsetattr(device_fd, 0, &termios) == 0) {
                        ret = flash_download(my_uart_recv, my_uart_send, my_firmware_recv, (void *)(intptr_t)device_fd, 2, (void *)(intptr_t)file_fd, 2, 0, NULL, 0x08003000, 0x08002800);
                    }
                }
                close(device_fd);
            }
        }
        close(file_fd);
    }

    if (errno) {
        perror(__func__);
    }
    return ret;
}
