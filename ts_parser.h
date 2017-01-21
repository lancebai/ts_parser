#ifndef PMT_PARSER_H
#define PMT_PARSER_H

#include <boost/noncopyable.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>
#define PKT_SIZE 188

/* pids */
#define PAT_PID                 0x0000
#define CAT_PID                 0x0001
#define TSDT_PID                0x0002
#define NIT_PID                 0x0010
#define SDT_PID                 0x0011

#define STREAM_TYPE_VIDEO_MPEG1     0x01
#define STREAM_TYPE_VIDEO_MPEG2     0x02
#define STREAM_TYPE_AUDIO_MPEG1     0x03
#define STREAM_TYPE_AUDIO_MPEG2     0x04
#define STREAM_TYPE_PRIVATE_SECTION 0x05
#define STREAM_TYPE_PRIVATE_DATA    0x06
#define STREAM_TYPE_AUDIO_AAC       0x0f
#define STREAM_TYPE_AUDIO_AAC_LATM  0x11
#define STREAM_TYPE_VIDEO_MPEG4     0x10
#define STREAM_TYPE_VIDEO_H264      0x1b
#define STREAM_TYPE_VIDEO_VC1       0xea
#define STREAM_TYPE_VIDEO_DIRAC     0xd1

#define STREAM_TYPE_AUDIO_AC3       0x81
#define STREAM_TYPE_AUDIO_DTS       0x8a

#define get_bit(val,bit) ((val & (1 << (bit))) >> (bit))

#define dump_flag(flag,text) if ( (flag) ) TSPARSER_DEBUG(" " << text)

enum debug_level {
    TRACE = 0,
    DEBUG,
    INFO ,
    WARN ,
    ERROR
};

debug_level default_debug_level = ERROR;

#define TSPARSER_PRINT(LEVEL ,x)                             \
    {                                                        \
        if(LEVEL >= default_debug_level) {                   \
            std::ostringstream os;                           \
            os << "TSPARSER " << #LEVEL << " "               \
               << ", #" << __LINE__ << ", " << x;            \
            std::string str(os.str());                       \
            std::cerr << str.c_str() << std::endl;           \
        }                                                    \
    }


#define TSPARSER_DEBUG(x) TSPARSER_PRINT(DEBUG,x)
#define TSPARSER_INFO(x)  TSPARSER_PRINT(INFO,x)
#define TSPARSER_ERROR(x) TSPARSER_PRINT(ERROR,x)
#define TSPARSER_WARN(x)  TSPARSER_PRINT(WARN,x)
#define TSPARSER_TRACE(x) TSPARSER_TRACE(WARN,x)

#define TSPARSER_LOG(x)                                      \
    {                                                        \
        std::ostringstream os;                               \
        os << x;                                             \
        std::string str(os.str());                           \
        std::cout << str.c_str() << std::endl;               \
    }

class IosFlagSaver : private boost::noncopyable {
public:
    explicit IosFlagSaver(std::ostream& _ios):
        ios(_ios),
        f(_ios.flags()) {
    }
    ~IosFlagSaver() {
        ios.flags(f);
    }

    // IosFlagSaver(const IosFlagSaver &rhs) = delete;
    // IosFlagSaver& operator= (const IosFlagSaver& rhs) = delete;

private:
    std::ostream& ios;
    std::ios::fmtflags f;
};

#define UNUSED(expr) do { (void)(expr); } while (0)

// TODO: make the structure little endian and big endian compact for parsing efficiency
typedef struct {
    uint8_t  sync_byte:8;             // Bit pattern of 0x47
    uint8_t  error_indicator:1;     // 1  Transport Error Indicator
    uint8_t  payload_flag:1;        // 1  psi_payload Unit Start Indicator, Set when a PES, PSI, or DVB-MIP packet begins immediately following the header.
    uint8_t  priority_flag:1;       // 1  Transport Priority. Set when the current packet has a higher priority than other packets with the same PID.
    uint16_t pid:13;                // 13 Packet ID
    uint8_t  scramble:2;            // 2  Transport scrambling control (0,1,2,3)
    uint8_t  adapt_field:2;         // 2  Adaptation field control (1,2,3)
    uint8_t  cc:4;                  // 4  Continuity counter

} TransportStreamHeader;


// TODO: make the structure little endian and big endian compact for parsing efficiency
// 3 bytes
typedef struct PSI_Table_Header {

    uint8_t  table_id:8;             // 8 table ID
    uint8_t  syntax_indicator:1;     // 1 section syntax indicator
    uint8_t  zero_bit:1;             // 1 private indicator
    uint8_t  reserved:2;             // 2 reserved
    uint16_t section_length:12;      // 12 The number of bytes that follow for the syntax section (with CRC value) and/or table data.
                                     // These bytes must not exceed a value of 1021.
} PSI_Table_Header;

typedef struct PSI_Table {
    PSI_Table_Header psi_header;
    virtual ~PSI_Table() {}
} PSI_Table;


typedef struct PES_Header {
    uint8_t  stream_id:8;
    uint16_t packet_length:16;
} PES_Header;

typedef struct PES_Optional_Header {
  uint8_t marker_bit:2 ;
  uint8_t scrambl:2;        // 00 implies not scrambled
  uint8_t prior_flag:1;
  uint8_t align_flag:1;     // 1 indicates that the PES packet header is immediately followed by the video start code or audio syncword
  uint8_t copyryght_flag:1; // 1 implies copyrighted
  uint8_t orig_flag:1;      // 1 implies original
  uint8_t pts_dts:2;        // 2 (11 = both present, 10 = only PTS
  uint8_t escr_flag:1;      // 1 ESCR flag
  uint8_t es_rate_flag:1;   // 1 ES rate flag
  uint8_t dsm_trick_mode_flag:1; // 1 DSM trick mode flag
  uint8_t add_copy_inf_flag:1;  // 1 Additional copy info flag
  uint8_t crc_flag:1;       // 1 CRC flag
  uint8_t ext_flag:1;       // 1 extension flag
  uint8_t data_len:8;       // 8 PES header data length

} PES_Optional_Header;


typedef struct PES_Packet {

    PES_Packet():pts(0), dts(0) {
        memset(&header, 0, sizeof(header));
        memset(&optional_header, 0, sizeof(optional_header));
    }

    bool isAudioStream() {
        if(header.stream_id >= 0xC0 &&  header.stream_id <= 0xDF) return true;
        return false;
    }

    bool isVideoStream() {
        if(header.stream_id >= 0xE0 &&  header.stream_id <= 0xEF) return true;
        return false;
    }

    uint64_t pts;
    uint64_t dts;
    PES_Header header;
    PES_Optional_Header optional_header;
} PES_Packet;

// TODO: make the structure little endian and big endian compact for parsing efficiency
typedef struct ProgramAssociationTable : public PSI_Table {
    uint16_t transport_stream_id:16;
    uint8_t  reserved:2;
    uint8_t  version_number:5;
    uint8_t  current_next_indicator:1;
    uint8_t  section_number:8;
    uint8_t  last_section_number:8;
    virtual ~ProgramAssociationTable(){};
} ProgramAssociationTable;

// TODO: make the structure little endian and big endian compact for parsing efficiency
typedef struct ProgramMapTable : public PSI_Table {
    uint16_t program_number:16;
    uint8_t  reserved:2;
    uint8_t  version_number:5;
    uint8_t  current_next_indicator:1;
    uint8_t  section_number:8;
    uint8_t  last_section_number:8;
    uint8_t  reserved2:3;
    uint16_t PCR_PID:13;
    uint8_t  reserved3:4;
    uint16_t program_info_length:12;
    //TODO: support descriptor
    virtual ~ProgramMapTable() {}

} ProgramMapTable;


// TODO: make the structure little endian and big endian compact for parsing efficiency
typedef struct PMTElementStreamInfo {
    uint8_t  stream_type:8;
    uint8_t  reserved:3;
    uint16_t elementary_PID:13;
    uint8_t  reserved2:4;
    uint16_t ES_info_length:12;
} PMTElementStreamInfo;

typedef struct PrivateSectionSyntax : public PSI_Table {
    virtual ~PrivateSectionSyntax();
} PrivateSectionSyntax;

typedef struct ConditionalAccessTable : public PSI_Table {
    virtual ~ConditionalAccessTable() {}
} ConditionalAccessTable;

// http://www.etherguidesystems.com/Help/SDOs/MPEG/Semantics/MPEG-2/adaptation_field.aspx
// https://en.wikipedia.org/wiki/MPEG_transport_stream
typedef struct AdaptationFieldMandatoryHeader {
    uint8_t adaptation_field_length:8;            // 8 Number of bytes in the adaptation field immediately following this byte
    uint8_t discontinuity_indicator:1;        // 1 Set to 1 if current TS packet is in a discontinuity state
    uint8_t random_access_indicator:1;  // 1 Set to 1 if the PES packet in this TS packet starts a video/audio sequence
    uint8_t elementary_stream_priority_indicator:1;       // 1 higher priority)
    uint8_t pcr_flag:1;       // 1 adaptation field does contain a PCR field
    uint8_t opcr_flag:1;      // 1 adaptation field does contain an OPCR field
    uint8_t splicing_point_flag:1;    // 1 splice countdown field in adaptation field
    uint8_t transport_private_data_flag:1;      // 1 private data bytes in adaptation field
    uint8_t adaptation_field_extension_flag:1;       // 1 adaptation field extension
} AdaptationFieldMandatoryHeader;


typedef struct AdaptationField {

    AdaptationFieldMandatoryHeader header;
    uint64_t                       pcr;
    uint64_t                       opcr;
    int8_t                         splice;
    AdaptationField():pcr(0), opcr(0), splice(0) {
        memset(&header, 0, sizeof(AdaptationFieldMandatoryHeader));
    }

    ~AdaptationField() {
    }

} AdaptationField;

class TransportStreamPacket {

    bool parse_pmt_esinfo(const uint8_t* buf, size_t* offset);
public:
    // TODO: Ecapsulate header and pmt_element_streams

    TransportStreamPacket(): packet_no(0), stream_offset(0) {
        memset(&header, 0, sizeof(TransportStreamHeader));
        TSPARSER_DEBUG(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    }

    bool hasAdaptionField() const {
        if(header.adapt_field & 0x2) return true;
        return false;
    }

    bool hasPayload() const {
        if(header.adapt_field & 0x01) return true;
        return false;
    }

    bool hasPSI() const {
        if(psi_payload != NULL) return true;
        return false;
    }

    bool hasPES() const {
        if(pes != NULL) return true;
        return false;
    }


    bool isPAT() const {
        if(header.pid == 0) return true;
        else return false;
    }

    bool isCAT() const {
        if(header.pid == 1) return true;
        else return false;
    }

    bool isTSD() const {
        if(header.pid == 3) return true;
        else return false;
    }

    bool isNIT() const {
        if(header.pid == 0x10) return true;
        else return false;
    }

    bool isEIT() const {
        if(header.pid == 0x12) return true;
        else return false;
    }

    bool isNullPacket() const {
        if(header.pid == 0x1FFF) return true;
        else return false;
    }

    bool isPMT() const {
        if(psi_payload != NULL && typeid(*psi_payload)==typeid(ProgramMapTable) && psi_payload->psi_header.table_id ==2) {
            return true;
        }

        return false;
    }

    void allocate_pmt() {
        if(psi_payload) {
            throw std::runtime_error("psi_payload is not NULL");
        }
        // psi_payload.reset(new PSI_Table());
        psi_payload.reset(new ProgramMapTable());
    }

    void free_pmt() {
        psi_payload.reset();
    }

    void allocate_pat() {
        psi_payload.reset(new ProgramAssociationTable());
    }

    void allocate_af() {
        af.reset(new AdaptationField());
    }

    void allocate_pes() {
        pes.reset(new PES_Packet());
    }


    ~TransportStreamPacket() {
        TSPARSER_DEBUG("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
    }

    size_t get_packet_no() const { return packet_no; }
    size_t get_stream_offset() const { return stream_offset; }

private:
    friend struct TransportStreamPacketInspector;
    friend struct TransportStreamParser;

    TransportStreamHeader header;
    boost::shared_ptr<AdaptationField> af;
    // FIXME: psi_payload can be more than PSI packet, ex: pes
    boost::shared_ptr<PSI_Table> psi_payload;
    boost::scoped_ptr<PES_Packet> pes;
    size_t packet_no; //for debugging purpose
    size_t stream_offset; //for debugging porpose

    std::vector<PMTElementStreamInfo> pmt_element_streams;

};



typedef struct TransportStreamPacketInspector {
    static void dump_ts_header(const TransportStreamPacket& ts_packet);
    static void dump_adaption_field(const TransportStreamPacket& ts_packet);
    static void dump_psi_header(const TransportStreamPacket& ts_packet);
    static void dump_pmt_es(const TransportStreamPacket& ts_packet);
    static void dump_pat(const TransportStreamPacket& ts_packet);
    static void dump_pes(const TransportStreamPacket& tspacket);
}TransportStreamPacketInspector;


typedef struct TransportStreamParser {
    static size_t packet_no;
    static bool parse_pat(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet);
    static bool __parse_pmt_esinfo(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet);
    static bool parse_pmt(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet);
    static bool parse_ts_packet(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet);
    static bool parse_adaption_field(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet);
    static uint64_t parse_pcr(const uint8_t *buf, size_t *pos, uint8_t *ext);
    static bool parsePES(const uint8_t* buf, size_t* offset, TransportStreamPacket& ts_packet);
}TransportStreamParser;

#endif