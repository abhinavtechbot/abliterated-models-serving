#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <IOKit/IOKitLib.h>

#define KERNEL_INDEX_SMC 2
#define SMC_CMD_READ_BYTES 5
#define SMC_CMD_READ_KEYINFO 9

typedef struct {
    char major;
    char minor;
    char build;
    char reserved[1];
    uint16_t release;
} SMCKeyData_vers_t;

typedef struct {
    uint16_t version;
    uint16_t length;
    uint32_t cpuPLimit;
    uint32_t gpuPLimit;
    uint32_t memPLimit;
} SMCKeyData_pLimitData_t;

typedef struct {
    uint32_t dataSize;
    uint32_t dataType;
    char dataAttributes;
} SMCKeyData_keyInfo_t;

typedef unsigned char SMCBytes_t[32];

typedef struct {
    uint32_t key;
    SMCKeyData_vers_t vers;
    SMCKeyData_pLimitData_t pLimitData;
    SMCKeyData_keyInfo_t keyInfo;
    char result;
    char status;
    char data8;
    uint32_t data32;
    SMCBytes_t bytes;
} SMCKeyData_t;

static uint32_t strtoul_key(const char *str) {
    return ((uint32_t)(unsigned char)str[0] << 24) |
           ((uint32_t)(unsigned char)str[1] << 16) |
           ((uint32_t)(unsigned char)str[2] << 8)  |
           ((uint32_t)(unsigned char)str[3]);
}

static void ultostr_type(uint32_t val, char *out) {
    out[0] = (char)(val >> 24);
    out[1] = (char)(val >> 16);
    out[2] = (char)(val >> 8);
    out[3] = (char)(val);
    out[4] = '\0';
}

static double read_smc_val(io_connect_t conn, const char *key_str) {
    SMCKeyData_t in_s, out_s;
    size_t out_len = sizeof(SMCKeyData_t);
    memset(&in_s, 0, sizeof(in_s));
    memset(&out_s, 0, sizeof(out_s));

    in_s.key = strtoul_key(key_str);
    in_s.data8 = SMC_CMD_READ_KEYINFO;
    if (IOConnectCallStructMethod(conn, KERNEL_INDEX_SMC, &in_s, sizeof(in_s), &out_s, &out_len) != kIOReturnSuccess)
        return -1.0;

    uint32_t data_size = out_s.keyInfo.dataSize;
    uint32_t data_type = out_s.keyInfo.dataType;
    if (data_size == 0) return -1.0;

    in_s.keyInfo.dataSize = data_size;
    in_s.data8 = SMC_CMD_READ_BYTES;
    out_len = sizeof(SMCKeyData_t);
    if (IOConnectCallStructMethod(conn, KERNEL_INDEX_SMC, &in_s, sizeof(in_s), &out_s, &out_len) != kIOReturnSuccess)
        return -1.0;

    char type_str[5];
    ultostr_type(data_type, type_str);

    if (strcmp(type_str, "sp78") == 0 && data_size == 2) {
        int16_t raw = ((int16_t)out_s.bytes[0] << 8) | out_s.bytes[1];
        return (double)raw / 256.0;
    } else if (strcmp(type_str, "fpe2") == 0 && data_size == 2) {
        uint16_t raw = ((uint16_t)out_s.bytes[0] << 8) | out_s.bytes[1];
        return (double)raw / 4.0;
    } else if (strcmp(type_str, "flt ") == 0 && data_size == 4) {
        float f = 0.0f;
        memcpy(&f, out_s.bytes, 4);
        return (double)f;
    } else if (strcmp(type_str, "ui16") == 0 && data_size == 2) {
        uint16_t raw = ((uint16_t)out_s.bytes[0] << 8) | out_s.bytes[1];
        return (double)raw;
    }
    return -1.0;
}

static double first_valid(io_connect_t conn, const char **keys, const char **matched) {
    for (int i = 0; keys[i] != NULL; i++) {
        double v = read_smc_val(conn, keys[i]);
        if (v > 5.0 && v < 135.0) {
            if (matched) *matched = keys[i];
            return v;
        }
    }
    return -1.0;
}

int main(void) {
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleSMC"));
    if (!svc) {
        printf("{\"ok\":false}\n");
        return 0;
    }
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    if (kr != kIOReturnSuccess) {
        printf("{\"ok\":false}\n");
        return 0;
    }

    const char *cpu_keys[] = {"TC0P", "TC0E", "TC0F", "TC0D", "TC1C", "TCXC", "TCGC", NULL};
    const char *gpu_keys[] = {"TG0D", "TG0P", "TG1D", "TGDD", "TCGC", NULL};
    const char *mem_keys[] = {"TM0P", "TM0S", "Ts0P", NULL};
    const char *bat_keys[] = {"TB0T", "TB1T", "TB2T", NULL};

    const char *cpu_k = "N/A", *gpu_k = "N/A", *mem_k = "N/A", *bat_k = "N/A";
    double cpu_c = first_valid(conn, cpu_keys, &cpu_k);
    double gpu_c = first_valid(conn, gpu_keys, &gpu_k);
    double mem_c = first_valid(conn, mem_keys, &mem_k);
    double bat_c = first_valid(conn, bat_keys, &bat_k);
    double fan0 = read_smc_val(conn, "F0Ac");
    double fan1 = read_smc_val(conn, "F1Ac");

    IOServiceClose(conn);

    printf("{\"ok\":true,\"cpu_temp_c\":%.1f,\"cpu_sensor\":\"%s\",\"gpu_temp_c\":%.1f,\"gpu_sensor\":\"%s\",\"mem_temp_c\":%.1f,\"battery_temp_c\":%.1f,\"fan0_rpm\":%.0f,\"fan1_rpm\":%.0f}\n",
           cpu_c, cpu_k, gpu_c, gpu_k, mem_c, bat_c, fan0 < 0 ? 0 : fan0, fan1 < 0 ? 0 : fan1);
    return 0;
}
