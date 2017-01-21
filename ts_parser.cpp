/*
 *  Filename    : ts_parser.cpp
 *  Author      : lancebai@gmail.com
 *  Description : parse Transport stream file to get pmt and pes information.
 *                ./ts_parser < ts_file > ts_report.log
 *  TODO        : parse pat, eit, nit, etc
 *              : improve the parsing efficiency by making header struct endiness alighnment, and read by words instead of bytes
 *
 */

#include <stdexcept>
#include <cstdio>  //fread
#include <cstdlib> //malloc, free
#include <cstring> //memcpy
#include <cstdint> //uint8_t, uint16_t, etc

#include <iostream>     // std::cout, std::ios
#include <iomanip>      // std::setiosflags, std::resetiosflags
#include <sstream>      // std::ostringstream
#include <vector>

#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include "ts_parser.h"

#define MAX_BUFFER 1024*188


const char* get_pid_description(int pid) {
    switch (pid) {
        case PAT_PID: return "Program Association Table (PAT)";
        case CAT_PID: return "Conditional Access Table (CAT)";
        case TSDT_PID: return "Transport Stream Description (TSDT)";
        case NIT_PID: return "Network Information Table (NIT)";
        case SDT_PID: return "Service Description Table (SDT)";
    }
    return "";
}

const char* get_pid_name(int pid) {
    switch (pid) {
        case 0x0000: return "PAT";
        case 0x0001: return "CAT";
        case 0x0010: return "NIT,ST";
        case 0x0011: return "SDT,BAT,ST";
        case 0x0012: return "EIT,ST_CIT";
        case 0x0013: return "RST,ST";
        case 0x0014: return "TDT,TOT,ST";
        case 0x0015: return "netwirk synchronization";
        case 0x0016: return "RNT";
        case 0x001c: return "inband signaling";
        case 0x001d: return "measurement";
        case 0x001e: return "DIT";
        case 0x001f: return "SIT";
    }
    return "";
}

const char* get_table_id_name(int pid) {
    switch (pid) {
        case 0x00: return "program association";
        case 0x01: return "conditional access";
        case 0x02: return "program map";
        case 0x03: return "transport stream description";
        // 0x04 - 0x3f "reserved"
        case 0x40: return "actual network info";
        case 0x41: return "other network info";
        case 0x42: return "actual service description";
        case 0x46: return "other service description";
        case 0x4a: return "bouquet association";
        case 0x4e: return "actual event info now";
        case 0x4f: return "other event info now";
        // 0x50 - 0x5f "event info actual schedule"
        // 0x60 - 0x6f "event info other schedule"
        case 0x70: return "time data";
        case 0x71: return "running status";
        case 0x72: return "stuffing";
        case 0x73: return "time offset";
        case 0x74: return "application information";
        case 0x75: return "container";
        case 0x76: return "related content";
        case 0x77: return "content id";
        case 0x78: return "MPE-FEC";
        case 0x79: return "resolution notification";
        case 0x7a: return "MPE-IFEC";
        // 0x7b - 0x7d "reserved"
        case 0x7e: return "discontinuity info";
        case 0x7f: return "selection info";
        // 0x80 - 0xfe "user defined"
        case 0xff: return "reserved";
    }
    return "reserved";
}


const char* get_stream_id_name(int stream_id) {
    switch (stream_id) {
        case 0x0000: return "reserved";
        case 0x0001: return "ISO/IEC 11172-2 (MPEG-1 Video)";
        case 0x0002: return "ISO/IEC 13818-2 (MPEG-2 Video)";
        case 0x0003: return "ISO/IEC 11172-3 (MPEG-1 Audio)";
        case 0x0004: return "ISO/IEC 13818-3 (MPEG-2 Audio)";
        case 0x0005: return "ISO/IEC 13818-1 (private section)";
        case 0x0006: return "ISO/IEC 13818-1 PES";
        case 0x0007: return "ISO/IEC 13522 MHEG";
        case 0x0008: return "ITU-T H.222.0 annex A DSM-CC";
        case 0x0009: return "ITU-T H.222.1";
        case 0x000a: return "ISO/IEC 13818-6 DSM-CC type A";
        case 0x000b: return "ISO/IEC 13818-6 DSM-CC type B";
        case 0x000c: return "ISO/IEC 13818-6 DSM-CC type C";
        case 0x000d: return "ISO/IEC 13818-6 DSM-CC type D";
        case 0x000e: return "ISO/IEC 13818-1 (auxiliary)";
        case 0x000f: return "ISO/IEC 13818-7 (AAC Audio)";
        case 0x0010: return "ISO/IEC 14496-2 (MPEG-4 Video)";
        case 0x0011: return "ISO/IEC 14496-3 (AAC LATM Audio)";
        case 0x001b: return "ITU-T H.264 (h264 Video)";
        case 0x0024: return "ITU-T Rec. H.265 and ISO/IEC 23008-2 (Ultra HD video) in a packetized stream";
        case 0x00ea: return "(VC-1 Video)";
        case 0x00d1: return "(DIRAC Video)";
        case 0x0081: return "(AC3 Audio)";
        case 0x008a: return "(DTS Audio)";
        case 0x00bd: return "(non-MPEG Audio, subpictures)";
        case 0x00be: return "(padding stream)";
        case 0x00bf: return "(navigation data)";
        //case 0x001e: return "";
        //case 0x001f: return "";
        default: {
          if ((stream_id >= 0xc0) && (stream_id <= 0xdf)) return "(AUDIO stream)";
          else if ((stream_id >= 0xe0) && (stream_id <= 0xef)) return "(VIDEO stream)";

        }
    }
    return "unknown stream type";
}



inline uint8_t get_8(const uint8_t *buf, size_t *offset) {
    uint8_t tmp8;
    tmp8 = buf[*offset];
    *offset += 1;
    return tmp8;
}

inline uint16_t get_16(const uint8_t *buf, size_t *offset) {
    uint16_t tmp16;
    tmp16 = buf[*offset+1] + (buf[*offset] << 8);
    *offset += 2;
    return tmp16;
}

inline uint32_t get_32(const uint8_t *buf, size_t *offset) {
    uint32_t tmp32;
    tmp32 = buf[*offset+3] + (buf[*offset+2] << 8) + (buf[*offset+1] << 16) + (buf[*offset] << 24);
    *offset += 4;
    return tmp32;
}

inline const char *get_str8(const uint8_t *buf, size_t *offset) {
    int len;
    char *str;

    len = get_8(buf, offset);
    if (len < 0) return NULL;
    str = (char*)malloc(len + 1);
    if (!str) return NULL;
    memcpy(str, &buf[*offset], len);
    str[len] = '\0';
    *offset += len;
    return str;
}

void dump_bits16(uint16_t n) {
    int i;
    //printf("%u=",n);
    for (i=15; i>=0; i--) {
        std::cout << ((n & (1 << i)) >> i);
        // printf("%u", ((n & (1 << i)) >> i));
        if ((i % 4) == 0) std::cout << " ";
    }
}


static bool locate_sync_byte(const uint8_t* buf, size_t buf_len, size_t* offset)
{
    size_t sync_byte;

    // find the first sync_byte
    for (sync_byte = *offset; sync_byte < buf_len; sync_byte++){
        if (buf[sync_byte] == 0x47 && buf[sync_byte + PKT_SIZE]==0x47 && buf[sync_byte + 2*PKT_SIZE]==0x47) {
            TSPARSER_DEBUG("##### the first sync byte is at " << sync_byte);
            *offset = sync_byte;
            return true;
        }
    }

    TSPARSER_ERROR("failed to locate sync byte");
    return false;

}

static bool __parse_psi_header(const uint8_t* buf, size_t* offset, PSI_Table_Header& psi_table_header)
{

    get_8(buf, offset); //skip_bytes
    psi_table_header.table_id = get_8(buf, offset);

    uint16_t tmp16 = get_16(buf, offset);
    psi_table_header.syntax_indicator = get_bit(tmp16, 15);
    psi_table_header.section_length = tmp16 & 0x0fff; // 000 1111

    // dump SI header
    {
        // dump header
        IosFlagSaver iosfs(std::cout);
        TSPARSER_DEBUG("  SI header: table_id=" << std::hex << std::showbase << static_cast<unsigned int>(psi_table_header.table_id) << " section_length=" << psi_table_header.section_length);
        dump_flag(psi_table_header.syntax_indicator, "syntax");

    }

    return  true;
}

bool TransportStreamParser::parse_pat(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet)
{
    ts_packet.allocate_pat();
    __parse_psi_header(buf, offset, ts_packet.psi_payload->psi_header);
    return true;
}


bool TransportStreamParser::__parse_pmt_esinfo(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet)
{

    PMTElementStreamInfo es;

    const boost::shared_ptr<const ProgramMapTable> pmt = boost::dynamic_pointer_cast<ProgramMapTable>(ts_packet.psi_payload);
    const size_t total_es_length = pmt->psi_header.section_length - 9 - pmt->program_info_length;
    size_t parsed_es_length = 0;



    while(parsed_es_length  < total_es_length ) {
        uint16_t tmp16;
        es.stream_type = get_8(buf, offset);
        tmp16 = get_16(buf, offset);
        es.reserved = 0xE000 & tmp16 >> 13; //1110 0000 0000 0000
        es.elementary_PID = 0x1FFF & tmp16;
        tmp16 = get_16(buf, offset);
        es.reserved2 = 0xF000 & tmp16 >> 12;
        es.ES_info_length = 0x0FFF &tmp16 ;

        ts_packet.pmt_element_streams.push_back(es);

        parsed_es_length += es.ES_info_length;
    }

    return true;

}

// return true if it is pmt packet
bool TransportStreamParser::parse_pmt(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet)
{
    ts_packet.allocate_pmt();
    const boost::shared_ptr<PSI_Table> psi_payload = ts_packet.psi_payload;
    __parse_psi_header(buf, offset, psi_payload->psi_header);
    if(psi_payload->psi_header.table_id ==2) {
        const boost::shared_ptr<ProgramMapTable> pmt = boost::dynamic_pointer_cast<ProgramMapTable>(psi_payload);

        pmt->program_number = get_16(buf, offset);
        uint8_t tmp8 = get_8(buf, offset);

        pmt->reserved = tmp8 & 0xC0 >> 6  ; // 1100 0000
        pmt->version_number = tmp8 & 0x3E >> 1 ; // 0011 1110
        pmt->current_next_indicator = tmp8 & 0x1; //0000 0001

        pmt->section_number = get_8(buf, offset);
        pmt->last_section_number = get_8(buf, offset);

        uint16_t tmp16 = get_16(buf, offset);

        pmt->reserved2 = tmp16 & 0xE000 >> 13 ;  //1110 0000 0000 0000
        pmt->PCR_PID = tmp16 & 0x1FFF; // 0001 1111 1111 1111

        tmp16 = get_16(buf, offset);
        pmt->reserved3 = tmp16 & 0xF000 >> 12;
        pmt->program_info_length = tmp16 & 0x0FFF;

        //skip the descriptor
        *offset += pmt->program_info_length;

        TransportStreamParser::__parse_pmt_esinfo(buf, offset, ts_packet);
        return true;
    }
    else {

        if(psi_payload->psi_header.table_id==0x81) { TSPARSER_DEBUG("ECM"); }
        IosFlagSaver iosfs(std::cout);
        TSPARSER_DEBUG("psi_header.table_id:" << std::hex << std::showbase << psi_payload->psi_header.table_id);

        // not a pmt, revert the psi header offset
        *offset -= sizeof(PSI_Table_Header);
        ts_packet.free_pmt();
        return false;
    }

}



// PCR field value
uint64_t TransportStreamParser::parse_pcr(const uint8_t *buf, size_t *pos, uint8_t *ext)
{
    // 33 base
    // 06 reserved
    // 09 extension
    uint64_t tmp64 = 0;
    uint8_t tmp8 = 0;


    for (size_t i = 0; i < 4; i++) {
        tmp64 |= get_8(buf, pos) << (8*(3-i));
    }
    tmp8 = get_8(buf, pos);
    tmp64 = (tmp64 << 1) | get_bit(tmp8, 7);

    if( ext!=NULL ) {
        *ext = (get_bit(tmp8, 0) << 8) | get_8(buf, pos);
    }

    return tmp64;
}


bool TransportStreamParser::parse_adaption_field(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet)
{
    ts_packet.allocate_af();
    const boost::shared_ptr<AdaptationField> af = ts_packet.af;

    // there can be stuffing bytes
    af->header.adaptation_field_length = get_8(buf, offset);

    // the offet of af content
    size_t af_content_offset = *offset;

    uint8_t tmp8 = get_8(buf, offset);
    af->header.discontinuity_indicator              = (tmp8 & 0x80) >> 7 ; //1000 0000
    af->header.random_access_indicator              = (tmp8 & 0x40) >> 6 ; //0100 0000
    af->header.elementary_stream_priority_indicator = (tmp8 & 0x20) >> 5 ; //0010 0000
    af->header.pcr_flag                             = (tmp8 & 0x10) >> 4 ; //0001 0000
    af->header.opcr_flag                            = (tmp8 & 0x08) >> 3 ; //0000 1000
    af->header.splicing_point_flag                  = (tmp8 & 0x04) >> 2 ; //0000 0100
    af->header.transport_private_data_flag          = (tmp8 & 0x02) >> 1 ; //0000 0010
    af->header.adaptation_field_extension_flag      = (tmp8 & 0x01)      ; //0000 0001

    if(af->header.pcr_flag == 1) {
        af->pcr = TransportStreamParser::parse_pcr(buf, offset, NULL);
    }

    if(af->header.opcr_flag == 1) {
        af->opcr = TransportStreamParser::parse_pcr(buf, offset, NULL);
    }

    if(af->header.splicing_point_flag == 1) {
        af->splice = get_8(buf, offset);
    }

    *offset = af_content_offset + af->header.adaptation_field_length;
    return true;
}

static uint64_t __parse_pes_pts(const uint8_t *buf, size_t *offset) {
  uint64_t tmp64;
  uint16_t tmp16;
  uint8_t tmp8;

  tmp8 = get_8(buf, offset);
  tmp64 =  ((int64_t)tmp8  >> 1) &0x07  << 30;
  tmp16 = get_16(buf, offset);
  tmp64 |= ((int64_t)tmp16 >> 1) << 15;
  tmp16 = get_16(buf, offset);
  tmp64 |= ((int64_t)tmp16  >> 1);

  return tmp64;
}

bool TransportStreamParser::parsePES(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet)
{
    // check for PES header
    // Packet start code prefix 3 bytes   0x000001

    uint16_t tmp16 = get_16(buf, offset);
    uint8_t tmp8 = get_8(buf, offset);
    if ((tmp16 == 0 && tmp8 == 1) != 1) {
        // it's not PES, rewind offset backward
        *offset -= 3;
        return false;
    }

    ts_packet.allocate_pes();

    PES_Header& header = ts_packet.pes->header;

    header.stream_id = get_8(buf, offset);
    header.packet_length = get_16(buf, offset);

    PES_Optional_Header& optional_header = ts_packet.pes->optional_header;

    tmp8 = get_8(buf, offset);
    optional_header.marker_bit = (tmp8 & 0xc0) >> 6 ; //1100 0000
    if(optional_header.marker_bit == 2) {
        optional_header.scrambl = (tmp8 & 0x30) >> 4; // 0011 0000
        optional_header.prior_flag = get_bit(tmp8, 3);
        optional_header.align_flag = get_bit(tmp8, 2);
        optional_header.copyryght_flag = get_bit(tmp8, 1);
        optional_header.orig_flag = get_bit(tmp8, 0);

        tmp8 = get_8(buf, offset);
        optional_header.pts_dts = (tmp8 & 0xc0) >> 6; //1100 0000
        optional_header.escr_flag = get_bit(tmp8, 5);
        optional_header.es_rate_flag = get_bit(tmp8, 4);
        optional_header.dsm_trick_mode_flag = get_bit(tmp8, 3);
        optional_header.add_copy_inf_flag = get_bit(tmp8, 2);
        optional_header.crc_flag = get_bit(tmp8, 1);
        optional_header.ext_flag = get_bit(tmp8, 0);
        optional_header.data_len = get_8(buf, offset);

        if (optional_header.pts_dts > 1) {
            ts_packet.pes->pts = __parse_pes_pts(buf, offset);
        }

        if (optional_header.pts_dts & 0x2) {
            ts_packet.pes->dts = __parse_pes_pts(buf, offset);
        }

    }


    return true;
}

void TransportStreamPacketInspector::dump_ts_header(const TransportStreamPacket& ts_packet)
{
    // std::cout << "sync_byte:" << static_cast<unsigned int>(header.sync_byte) << std::endl;
    const TransportStreamHeader& header = ts_packet.header;
    IosFlagSaver iosfs(std::cout);
    TSPARSER_LOG("\tTS Header(4 Bytes)");
    TSPARSER_LOG("\t-----------------------------------");
    TSPARSER_LOG("\tsync_byte        : " << std::hex << std::showbase << static_cast<unsigned int>(header.sync_byte));
    TSPARSER_LOG("\terror_indicator  : " << static_cast<unsigned int>(header.error_indicator));
    TSPARSER_LOG("\tpayload_flag     : " << static_cast<unsigned int>(header.payload_flag       ));
    TSPARSER_LOG("\tpriority_flag    : " << static_cast<unsigned int>(header.priority_flag      ));
    TSPARSER_LOG("\tpid              : " << std::hex << std::showbase << header.pid                                           );
    TSPARSER_LOG("\tscramble         : " << static_cast<unsigned int>(header.scramble           ));
    TSPARSER_LOG("\tadapt_field      : " << static_cast<unsigned int>(header.adapt_field        ));
    TSPARSER_LOG("\tcc               : " << static_cast<unsigned int>(header.cc                 ));
    TSPARSER_LOG("\n");
}

void TransportStreamPacketInspector::dump_pes(const TransportStreamPacket& ts_packet)
{
    // std::cout << "sync_byte:" << static_cast<unsigned int>(header.sync_byte) << std::endl;
    const PES_Header& header = ts_packet.pes->header;
    const PES_Optional_Header& optional_header = ts_packet.pes->optional_header;
    IosFlagSaver iosfs(std::cout);

    std::string pes_packet_type;
    if(ts_packet.pes->isVideoStream()) {
        pes_packet_type = "video stream";
    }
    else if(ts_packet.pes->isAudioStream()) {
        pes_packet_type = "audio stream";
    }
    else {
        pes_packet_type = "data";
    }



    TSPARSER_LOG("\tPES Packet ( " << pes_packet_type << " )" );
    TSPARSER_LOG("\t-----------------------------------");
    TSPARSER_LOG("\tstream_id:              : " << std::hex << std::showbase << static_cast<unsigned int>(header.stream_id) << ", " << get_stream_id_name(header.stream_id));
    TSPARSER_LOG("\tpacket_length           : " << header.packet_length);

    if(optional_header.marker_bit == 2) {
        TSPARSER_LOG("\tscrambl                 : " << static_cast<unsigned int>(optional_header.scrambl));
        TSPARSER_LOG("\tprior_flag              : " << static_cast<unsigned int>(optional_header.prior_flag));
        TSPARSER_LOG("\talign_flag              : " << static_cast<unsigned int>(optional_header.align_flag));
        TSPARSER_LOG("\tcopyryght_flag          : " << static_cast<unsigned int>(optional_header.copyryght_flag));
        TSPARSER_LOG("\torig_flag               : " << static_cast<unsigned int>(optional_header.orig_flag));
        TSPARSER_LOG("\tpts_dts                 : " << static_cast<unsigned int>(optional_header.pts_dts));
        TSPARSER_LOG("\tescr_flag               : " << static_cast<unsigned int>(optional_header.escr_flag));
        TSPARSER_LOG("\tes_rate_flag            : " << static_cast<unsigned int>(optional_header.es_rate_flag));
        TSPARSER_LOG("\tdsm_trick_mode_flag     : " << static_cast<unsigned int>(optional_header.dsm_trick_mode_flag));
        TSPARSER_LOG("\tadd_copy_inf_flag       : " << static_cast<unsigned int>(optional_header.add_copy_inf_flag));
        TSPARSER_LOG("\tcrc_flag                : " << static_cast<unsigned int>(optional_header.crc_flag));
        TSPARSER_LOG("\text_flag                : " << static_cast<unsigned int>(optional_header.ext_flag));
        TSPARSER_LOG("\tdata_len                : " << static_cast<unsigned int>(optional_header.data_len));

        // 11 = both present, 01 is forbidden, 10 = only PTS, 00 = no PTS or DTS
        if (optional_header.pts_dts > 1) {
            TSPARSER_LOG("\tpts                     : " << ts_packet.pes->pts);
        }

        if (optional_header.pts_dts == 3) {
            TSPARSER_LOG("\tdts                     : " << ts_packet.pes->dts);
        }

    }

    TSPARSER_LOG("\n");
}


void TransportStreamPacketInspector::dump_pmt_es(const TransportStreamPacket& ts_packet)
{
    const std::vector<PMTElementStreamInfo>& pmt_element_streams = ts_packet.pmt_element_streams;
    TSPARSER_LOG("\tElement Streams");
    TSPARSER_LOG("\t-----------------------------------");
    for (std::vector<PMTElementStreamInfo>::const_iterator it = pmt_element_streams.begin(); it != pmt_element_streams.end(); ++it) {
            IosFlagSaver iosfs(std::cout);
            TSPARSER_LOG("\tPMT elementary stream type=" << std::hex << std::showbase << static_cast<unsigned int>(it->stream_type) << " pid=" << it->elementary_PID);
            TSPARSER_LOG("\t" << get_stream_id_name(it->stream_type));
            TSPARSER_LOG("\t  info length:" << std::noshowbase << std::dec << it->ES_info_length);
    }
}

void TransportStreamPacketInspector::dump_pat(const TransportStreamPacket& ts_packet)
{
    UNUSED(ts_packet);
    TSPARSER_LOG("is a PAT packet");
    // not implemented yet
}


void TransportStreamPacketInspector::dump_adaption_field(const TransportStreamPacket& ts_packet)
{
    const boost::shared_ptr<const AdaptationField> af = ts_packet.af;
    TSPARSER_LOG("\tAdaption Field");
    TSPARSER_LOG("\t-----------------------------------");
    TSPARSER_LOG("\tadaptation_field_length : " << static_cast<unsigned int>(af->header.adaptation_field_length));
    TSPARSER_LOG("\tdiscontinuity_indicator : " << static_cast<unsigned int>(af->header.discontinuity_indicator));
    TSPARSER_LOG("\trandom_access_indicator : " << static_cast<unsigned int>(af->header.random_access_indicator));
    TSPARSER_LOG("\tes_priority_indicator   : " << static_cast<unsigned int>(af->header.elementary_stream_priority_indicator));
    TSPARSER_LOG("\tpcr_flag                : " << static_cast<unsigned int>(af->header.pcr_flag));
    TSPARSER_LOG("\topcr_flag               : " << static_cast<unsigned int>(af->header.opcr_flag));
    TSPARSER_LOG("\tsplicing_point_flag     : " << static_cast<unsigned int>(af->header.splicing_point_flag));
    TSPARSER_LOG("\ttransport_private_data  : " << static_cast<unsigned int>(af->header.transport_private_data_flag));
    TSPARSER_LOG("\tadaptation_field_ext    : " << static_cast<unsigned int>(af->header.adaptation_field_extension_flag));
    TSPARSER_LOG("\tpcr: " << af-> pcr << ", opcr: " << af->opcr << ", splice: " << static_cast<unsigned int>(af->splice));
    TSPARSER_LOG("\n");
}


void TransportStreamPacketInspector::dump_psi_header(const TransportStreamPacket& ts_packet)
{
    const PSI_Table_Header& psi_header = ts_packet.psi_payload->psi_header;
    TSPARSER_LOG("\tPSI Header");
    TSPARSER_LOG("\t-----------------------------------");
    TSPARSER_LOG("\ttable_id               : " << static_cast<unsigned int>(psi_header.table_id));
    TSPARSER_LOG("\tsyntax_indicator       : " << static_cast<unsigned int>(psi_header.syntax_indicator));
    TSPARSER_LOG("\tzero_bit               : " << static_cast<unsigned int>(psi_header.zero_bit));
    TSPARSER_LOG("\treserved               : " << static_cast<unsigned int>(psi_header.reserved));
    TSPARSER_LOG("\tsection_length         : " << psi_header.section_length);
    TSPARSER_LOG("\n");
}



static bool __parse_ts_header(const uint8_t* buf, size_t* offset, TransportStreamHeader& ts_header)
{

    uint16_t tmp16;
    uint8_t tmp8;

    if (buf[*offset] != 0x47) return false;
    ts_header.sync_byte = 0x47;
    *offset += 1;

    tmp16 = get_16(buf, offset);
    // dump_16(tmp16); printf(" \n");
    ts_header.error_indicator = get_bit(tmp16, 15);
    ts_header.payload_flag = get_bit(tmp16, 14);
    ts_header.priority_flag = get_bit(tmp16, 13);
    ts_header.pid = tmp16 & 0x1fff; // 0x1f = 0001 1111

    tmp8 = get_8(buf, offset);
    ts_header.scramble = (tmp8 & 0xc0) >> 6;    // 0xc0 = 1100 0000
    ts_header.adapt_field = (tmp8 & 0x30) >> 4; // 0x30 = 0011 0000
    ts_header.cc = tmp8 & 0x0f;                 // 0000 1111

    return true;
}


bool TransportStreamParser::parse_ts_packet(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet)
{
    ts_packet.stream_offset = *offset;
    packet_no ++;
    ts_packet.packet_no = packet_no;
    __parse_ts_header(buf, offset, ts_packet.header);

    if(ts_packet.hasAdaptionField()) {
        TransportStreamParser::parse_adaption_field(buf, offset, ts_packet);
    }

    TransportStreamHeader& header = ts_packet.header;
    switch(header.pid) {
        case 0x0000:
            TSPARSER_DEBUG("PAT table");
            TransportStreamParser::parse_pat(buf, offset, ts_packet);
            return true;
        case 0x0001:
            TSPARSER_DEBUG("Conditional Access Table");
            return true;
        case 0x0002:
            TSPARSER_DEBUG("Transport Stream Description section");
            return true;
        case 0x0003:
            TSPARSER_DEBUG("TSD");
            return true;
        case 0x0010:
            TSPARSER_DEBUG("NIT");
            return true;
        case 0x0012:
            TSPARSER_DEBUG("EIT");
            return true;
        case 0x1FFF:
            TSPARSER_DEBUG("NULL Packet");
            return true;
        default:
        {
            if(header.pid >= 0x0020 && header.pid <=  0x1FFA) {
                TSPARSER_DEBUG(packet_no <<" : May be assigned as needed to Program Map Tables, elementary streams and other data tables");
                if(header.payload_flag) {
                    //parse pmt

                    if(TransportStreamParser::parse_pmt(buf, offset, ts_packet) == false) {
                        TSPARSER_DEBUG("has payload but not a pmt packet");
                    }

                    if(TransportStreamParser::parsePES(buf, offset, ts_packet)) {
                        TSPARSER_DEBUG(packet_no << " is a pes packet");
                    }
                }
            }

            break;
        }
    }

    return true;

}

size_t TransportStreamParser::packet_no = 0;

int main(int argc, char**argv) {

    uint8_t data_buffer[MAX_BUFFER];
    size_t buffer_pos, first_sync_byte = 0;

    size_t bytes_read = fread(data_buffer, 1, MAX_BUFFER, stdin);

    if (bytes_read != MAX_BUFFER) {
        throw std::runtime_error("failed to read data");
    }

    if(locate_sync_byte(data_buffer, bytes_read, &first_sync_byte) ==false) {
        return -1;
    }

    buffer_pos = first_sync_byte;

    size_t idx;
    std::vector<boost::shared_ptr<TransportStreamPacket> > tspackets;
    for(idx = 1, buffer_pos = first_sync_byte ; buffer_pos < bytes_read; buffer_pos = first_sync_byte + idx* PKT_SIZE, idx++) {
        boost::shared_ptr<TransportStreamPacket> ts_packet_ptr = boost::make_shared<TransportStreamPacket>();

        if(TransportStreamParser::parse_ts_packet(data_buffer, &buffer_pos, *ts_packet_ptr) == false) {
            return -1;
        }

        tspackets.push_back(ts_packet_ptr);
    }

    for (std::vector<boost::shared_ptr<TransportStreamPacket> >::const_iterator it = tspackets.begin() ; it != tspackets.end(); ++it){
        // std::cout << (*it)->get_packet_no(); //do not change line
        // ScopedCoutAsHex cout_as_hex;
        IosFlagSaver iosfs(std::cout);
        TSPARSER_LOG((*it)->get_packet_no() << ":  offset: " << std::showbase << std::internal << std::setfill('0') << std::hex << std::setw(6) << (*it)->get_stream_offset() << std::endl);
        TransportStreamPacketInspector::dump_ts_header(*(*it));
        if((*it)->hasAdaptionField()) TransportStreamPacketInspector::dump_adaption_field(*(*it));
        if((*it)->hasPSI()) TransportStreamPacketInspector::dump_psi_header(*(*it));
        if((*it)->isPMT()) TransportStreamPacketInspector::dump_pmt_es(*(*it));
        if((*it)->isPAT()) TransportStreamPacketInspector::dump_pat(*(*it));
        if((*it)->hasPES()) TransportStreamPacketInspector::dump_pes(*(*it));
        TSPARSER_LOG("============================================");
    }

}
