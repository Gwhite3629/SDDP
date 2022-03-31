#include <stdbool.h>
#include <stdint.h>

#define uint unsigned int

// typedef enum STATE {};
// typedef enum TRUST {};

typedef struct sender {
    // STATE state;
} SENDER_T;

typedef struct header{
    uint32_t size;
    uint8_t size_ext;
    uint8_t data_type;
    uint16_t cipher_key;
    uint16_t cipher_key;
    uint8_t total_packets;
    uint8_t packet_number;
} HEADER;

typedef struct address {
    // TRUST trust;
    char *hostname;
    uint address;
    uint key;
    uint index;
} ADDRESS_T;

typedef struct AddressBook {
    ADDRESS_T *members;
} ADDRESSBOOK_T;

typedef struct receiver{
    // STATE state;

    // Packet info
    bool *packets;  // List of packets
                    // Total size = N_packets_T
                    // 1: Received packet
                    // 0: Missing packet
    uint8_t N_packets_M; // Number of missing packets
    uint8_t N_packets_R; // Number of received packets
    uint8_t N_packets_T; // Number of total packets

} RECEIVER_T;

// create_header();
// gen_cipher();
// cipher();
// get_addressbook();
// read_file();
// reject();
// block();
// checksum();