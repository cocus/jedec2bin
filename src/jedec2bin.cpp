#include <iostream>
#include <iomanip>
#include <string>
#include <functional>
#include <fstream>
#include <bitset>
#include <cstdlib>
#include <list>
#include <vector>
#include <map>

class JedecBlock
{
    public:
        enum class JedecBlockType
        {
            COMMENT,
            FUSE_CHECKSUM,
            FUSE_DATA,
            END_DATA,
            FUSE_LIST,
            FUSE_STATE,
            SECURITY_FUSE,
            FUSE_DEFAULT,
            FUSE_SIZE,
            USER_CODE,
            PIN_COUNT,
            FEATURE_ROW,
            DONE,
            UNKNOWN
        };

        JedecBlock(JedecBlockType t, std::string v) :
            _type(t), _raw_value(v) { };

        const JedecBlockType get_type() const { return _type; };
        const std::string get_raw_value() const { return _raw_value; };

        virtual bool try_parse() { };
    protected:
        JedecBlockType _type;
        std::string _raw_value;
};


class JedecBlockFuseList : public JedecBlock
{
    public:
        JedecBlockFuseList(JedecBlockType t, std::string v) :
            JedecBlock(t, v) { };
        
        bool try_parse();

        const uint get_fuses_pos() const { return _fuses_pos; }
        const uint get_fuses_length() const { return _fuses_length; }
        const std::bitset<32> get_bits() const { return _fuses; }
 
    private:
        enum class ParserState
        {
            PARSE_LOOKING_FOR_L,
            PARSE_READING_POS,
            PARSE_SPACE,
            PARSE_READING_FUSES
        };

        std::bitset<32> _fuses;
        uint _fuses_pos;
        uint _fuses_length;
};

bool JedecBlockFuseList::try_parse()
{
    ParserState state = ParserState::PARSE_LOOKING_FOR_L;
    std::string fuses_pos;
    std::size_t fuse_pos = 0;
    
    //std::cout << "JedecBlockFuseList with string " << std::quoted(_raw_value) << std::endl;

    for (auto & x : _raw_value)
    {
        switch (state)
        {
            case ParserState::PARSE_LOOKING_FOR_L:
            {
                if (x == 'L' || x == 'l')
                {
                    state = ParserState::PARSE_READING_POS;
                }
                break;
            }
            case ParserState::PARSE_READING_POS:
            {
                if (x == ' ')
                {
                    _fuses_pos = std::atol(fuses_pos.c_str());
                    _fuses_length = 0;
                    state = ParserState::PARSE_READING_FUSES;
                }
                else
                {
                    fuses_pos += x;
                }
                break;
            }
            case ParserState::PARSE_READING_FUSES:
            {
                fuse_pos++;

                _fuses_length++;

                if (_fuses.size() < fuse_pos)
                {
                    // overflow!
                    return false;
                }

                _fuses[_fuses.size() - fuse_pos] = x == '1';
                break;
            }
        }
    }

    //std::cout << "JedecBlockFuseList pos = " << _fuses_pos << std::endl;
    //std::cout << "JedecBlockFuseList fuses_length = " << _fuses_length << std::endl;
    //std::cout << "JedecBlockFuseList fuses = " << std::quoted(_fuses.to_string()) << std::endl;

    return true;
}




class JedecBlockSecurityFuse : public JedecBlock
{
    public:
        JedecBlockSecurityFuse(JedecBlockType t, std::string v) :
            JedecBlock(t, v) { };
        
        bool try_parse();

        const bool get_is_set() const { return _is_set; }
 
    private:
        bool _is_set;
};

bool JedecBlockSecurityFuse::try_parse()
{
    //std::cout << "JedecBlockSecurityFuse with string " << std::quoted(_raw_value) << std::endl;

    if (_raw_value.length() != 2)
    {
        return false;
    }

    if (_raw_value.at(0) != 'G' && _raw_value.at(0) != 'g')
    {
        return false;
    }

    _is_set = _raw_value.at(1) == '1';

    //std::cout << "JedecBlockSecurityFuse is_set = " << _is_set << std::endl;

    return true;
}




class JedecBlockDefaultFuseValue : public JedecBlock
{
    public:
        JedecBlockDefaultFuseValue(JedecBlockType t, std::string v) :
            JedecBlock(t, v) { };
        
        bool try_parse();

        const bool get_default() const { return _default; }
 
    private:
        bool _default;
};

bool JedecBlockDefaultFuseValue::try_parse()
{
    //std::cout << "JedecBlockDefaultFuseValue with string " << std::quoted(_raw_value) << std::endl;

    if (_raw_value.length() != 2)
    {
        return false;
    }

    if (_raw_value.at(0) != 'F' && _raw_value.at(0) != 'f')
    {
        return false;
    }

    _default = _raw_value.at(1) == '1';

    //std::cout << "JedecBlockDefaultFuseValue default = " << _default << std::endl;

    return true;
}




class JedecBlockFuseChecksum : public JedecBlock
{
    public:
        JedecBlockFuseChecksum(JedecBlockType t, std::string v) :
            JedecBlock(t, v) { };
        
        bool try_parse();

        const uint get_checksum() const { return _cheksum; }
 
    private:
        uint _cheksum;
};

bool JedecBlockFuseChecksum::try_parse()
{
    //std::cout << "JedecBlockFuseChecksum with string " << std::quoted(_raw_value) << std::endl;

    if (_raw_value.length() < 3)
    {
        return false;
    }

    if (_raw_value.at(0) != 'C' && _raw_value.at(0) != 'c')
    {
        return false;
    }

    _cheksum = std::stoi(_raw_value.c_str() + 1, nullptr, 16);

    //std::cout << "JedecBlockPinCount cheksum = " << _cheksum << std::endl;

    return true;
}




class JedecBlockPinCount : public JedecBlock
{
    public:
        JedecBlockPinCount(JedecBlockType t, std::string v) :
            JedecBlock(t, v) { };
        
        bool try_parse();

        const uint get_count() const { return _count; }
 
    private:
        uint _count;
};

bool JedecBlockPinCount::try_parse()
{
    //std::cout << "JedecBlockPinCount with string " << std::quoted(_raw_value) << std::endl;

    if (_raw_value.length() < 3)
    {
        return false;
    }

    if (_raw_value.at(0) != 'G' && _raw_value.at(0) != 'g' &&
        _raw_value.at(1) != 'P' && _raw_value.at(1) != 'p')
    {
        return false;
    }

    _count = std::atol(_raw_value.c_str() + 2);

    //std::cout << "JedecBlockPinCount count = " << _count << std::endl;

    return true;
}




class JedecBlockBitstreamSize : public JedecBlock
{
    public:
        JedecBlockBitstreamSize(JedecBlockType t, std::string v) :
            JedecBlock(t, v) { };
        
        bool try_parse();

        const uint get_size() const { return _size; }
 
    private:
        uint _size;
};

bool JedecBlockBitstreamSize::try_parse()
{
    //std::cout << "JedecBlockBitstreamSize with string " << std::quoted(_raw_value) << std::endl;

    if (_raw_value.length() < 3)
    {
        return false;
    }

    if (_raw_value.at(0) != 'G' && _raw_value.at(0) != 'g' &&
        _raw_value.at(1) != 'F' && _raw_value.at(1) != 'f')
    {
        return false;
    }

    _size = std::atol(_raw_value.c_str() + 2);

    //std::cout << "JedecBlockBitstreamSize size = " << _size << std::endl;

    return true;
}



class Jedec
{
    public:
        Jedec() { };

        JedecBlock::JedecBlockType add_info_from_block(std::ifstream& block);

        const bool get_fuse_bit(uint bitnum) const { return _bitmap.count(bitnum) ? _bitmap.at(bitnum) : _default_fuse; }

        const std::map<uint, bool> get_bitmap() const { return _bitmap; }
        const uint get_bitstream_size() const { return _bitstream_size; }
        const uint get_pin_count() const { return _pin_count; }
        const uint get_checksum() const { return _checksum; }
        const bool get_default_fuse() const { return _default_fuse; }
        const bool get_security_set() const { return _security_set; }

    protected:
        std::map<uint, bool> _bitmap;
        uint _bitstream_size = 0;
        uint _pin_count = 0;
        uint _checksum = 0;
        bool _default_fuse = 0;
        bool _security_set = 0;
};


JedecBlock::JedecBlockType Jedec::add_info_from_block(std::ifstream& infile)
{
    char x;
    std::string block;

    do
    {
        x = infile.get();
        /// discard CR, LF, ETX and the token itself
        switch (x)
        {
            case 0x0D:
            case 0x0A:
            case '*':
            case 0x03:
            {
                continue;
            }
        }
        block += x;
    } while(infile && x != '*' && x != 0x03);


    if (x == 0x03)
    {
        // fill gaps
        for (std::size_t bit = 0; bit < _bitstream_size; bit++)
        {
            if (_bitmap.count(bit) == 0)
            {
                _bitmap[bit] = _default_fuse;
            }
        }

        return JedecBlock::JedecBlockType::DONE;
    }

    if (block.length() < 2)
    {
        return JedecBlock::JedecBlockType::UNKNOWN;
    }

    switch (block.at(0))
    {
        case 'L':
        case 'l':
        {
            auto ret = JedecBlockFuseList(JedecBlock::JedecBlockType::FUSE_LIST, block);
            if (!ret.try_parse())
            {
                break;
            }
            auto base_pos = ret.get_fuses_pos();
            auto fuses_length = ret.get_fuses_length();
            auto& map = ret.get_bits();
            std::size_t bitnum = map.size() - 1;
            std::size_t zero_based_bitnum;

            for (zero_based_bitnum = 0; zero_based_bitnum < fuses_length; zero_based_bitnum++)
            {
                //std::cout << "At " << base_pos + zero_based_bitnum << ", got bit = " << map[bitnum] << std::endl;
                
                _bitmap[base_pos + zero_based_bitnum] = map[bitnum];
                
                bitnum--;
            }
            return ret.get_type();
        }

        case 'F':
        case 'f':
        {
            auto ret = JedecBlockDefaultFuseValue(JedecBlock::JedecBlockType::FUSE_DEFAULT, block);
            if (!ret.try_parse())
            {
                break;
            }
            _default_fuse = ret.get_default();
            return ret.get_type();
        }

        case 'G':
        case 'g':
        {
            auto ret = JedecBlockSecurityFuse(JedecBlock::JedecBlockType::SECURITY_FUSE, block);
            if (!ret.try_parse())
            {
                break;
            }
            _security_set = ret.get_is_set();
            return ret.get_type();
        }

        case 'C':
        case 'c':
        {
            auto ret = JedecBlockFuseChecksum(JedecBlock::JedecBlockType::FUSE_CHECKSUM, block);
            if (!ret.try_parse())
            {
                break;
            }
            _checksum = ret.get_checksum();
            return ret.get_type();
        }


        case 'Q':
        case 'q':
        {
            switch (block.at(1))
            {
                case 'P':
                case 'p':
                {
                    auto ret = JedecBlockPinCount(JedecBlock::JedecBlockType::PIN_COUNT, block);
                    if (!ret.try_parse())
                    {
                        break;
                    }
                    _pin_count = ret.get_count();
                    return ret.get_type();
                }

                case 'F':
                case 'f':
                {
                    auto ret = JedecBlockBitstreamSize(JedecBlock::JedecBlockType::FUSE_SIZE, block);
                    if (!ret.try_parse())
                    {
                        break;
                    }
                    _bitstream_size = ret.get_size();
                    return ret.get_type();
                }

                default:
                {
                    break;
                }
            }
            break;
        }

        default:
        {
            break;
        }
    }

    return JedecBlock::JedecBlockType::UNKNOWN;
}

class GAL16V8
{
    public:
        GAL16V8(const Jedec& jedec);

    private:
        const Jedec& _jedec;

        bool _SYN = false;
        bool _AC0 = false;

        std::bitset<64> _user_signature;

        // column, IO
        std::map<uint, const std::tuple<uint, bool>> _columns = {
            { 0, std::make_tuple(2, false) },
            { 1, std::make_tuple(2, true) },
            { 2, std::make_tuple(19, false) },
            { 3, std::make_tuple(19, true) },

            { 4, std::make_tuple(3, false) },
            { 5, std::make_tuple(3, true) },
            { 6, std::make_tuple(18, false) },
            { 7, std::make_tuple(18, true) },

            { 8, std::make_tuple(4, false) },
            { 9, std::make_tuple(4, true) },
            { 10, std::make_tuple(17, false) },
            { 11, std::make_tuple(17, true) },

            { 12, std::make_tuple(5, false) },
            { 13, std::make_tuple(5, true) },
            { 14, std::make_tuple(16, false) },
            { 15, std::make_tuple(16, true) },

            { 16, std::make_tuple(6, false) },
            { 17, std::make_tuple(6, true) },
            { 18, std::make_tuple(15, false) },
            { 19, std::make_tuple(15, true) },

            { 20, std::make_tuple(7, false) },
            { 21, std::make_tuple(7, true) },
            { 22, std::make_tuple(14, false) },
            { 23, std::make_tuple(14, true) },

            { 24, std::make_tuple(8, false) },
            { 25, std::make_tuple(8, true) },
            { 26, std::make_tuple(13, false) },
            { 27, std::make_tuple(13, true) },

            { 28, std::make_tuple(9, false) },
            { 29, std::make_tuple(9, true) },
            { 30, std::make_tuple(12, false) },
            { 31, std::make_tuple(12, true) },
        }; // 32

        // list of fuses blown on each row
        std::vector<std::list<uint>> _rows; // 64


        std::map<uint, std::tuple<uint, uint, uint>> _olmc_configs = {
            { 0, std::make_tuple(2048, 2120, 19) },
            { 1, std::make_tuple(2049, 2121, 18) },
            { 2, std::make_tuple(2050, 2122, 17) },
            { 3, std::make_tuple(2051, 2123, 16) },
            { 4, std::make_tuple(2052, 2124, 15) },
            { 5, std::make_tuple(2053, 2125, 14) },
            { 6, std::make_tuple(2054, 2126, 13) },
            { 7, std::make_tuple(2055, 2127, 12) }
        }; // xor, ac1, out_pin row for each OLMC
};


GAL16V8::GAL16V8(const Jedec& jedec)
    : _jedec(jedec)
{
    _SYN = _jedec.get_fuse_bit(2192);
    _AC0 = _jedec.get_fuse_bit(2193);

    std::size_t sig_bitnum = 0;
    for (std::size_t bit = 2056; bit < 2120; bit++)
    {
        _user_signature[sig_bitnum++] = _jedec.get_fuse_bit(bit); 
    }

    std::cout << "GAL16V8 SYN=" << _SYN << ", AC0=" << _AC0 << std::endl;
    std::cout << "GAL16V8 User Signature=" << _user_signature.to_string() << std::endl;

    for (std::size_t olmc_num = 0; olmc_num < _olmc_configs.size(); olmc_num++)
    {
        // check if the pin is used as an input, thus this OLMC is disabled
        if (_jedec.get_fuse_bit(std::get<1>(_olmc_configs[olmc_num])))
        {
            std::cout << "GAL16V8 olmc=" << olmc_num << ", disabled (pin " << std::get<2>(_olmc_configs[olmc_num]) << " marked as input)" << std::endl;
            continue;
        }

        std::list<std::list<uint>> col_products;

        for (std::size_t olmc_prod_row = 0; olmc_prod_row < 8; olmc_prod_row++)
        {
            // check for PTD fuse blow for this row
            if (!_jedec.get_fuse_bit(2128 + (olmc_num * 8) + olmc_prod_row))
            {
                // skip term
                continue;
            }
            std::list<uint> blown_fuses;

            for (std::size_t column = 0; column < _columns.size(); column++)
            {
                uint fuse = (olmc_num * _olmc_configs.size() * _columns.size()) + (olmc_prod_row * _columns.size()) + column;
                if (!_jedec.get_fuse_bit(fuse))
                {
                    blown_fuses.push_back(column);
                }
            }

            if (blown_fuses.size() == 32)
            {
                //std::cout << "GAL16V8 olmc=" << olmc_num << ", discarded row=" << olmc_prod_row << std::endl;
            }
            else
            {
                col_products.push_back(blown_fuses);

                //std::cout << "GAL16V8 olmc=" << olmc_num << ", row=" << olmc_prod_row << std::endl;
            }
        }

        std::string full_product = "pin" + std::to_string(std::get<2>(_olmc_configs[olmc_num])) + "=";

        // if XOR is not set, then the whole product is negated
        if (!_jedec.get_fuse_bit(std::get<0>(_olmc_configs[olmc_num])))
        {
            full_product += "/{";
        }

        for (auto& term : col_products)
        {
            bool first_fuse = true;

            full_product += " (";

            for (auto& f_col : term)
            {
                if (!first_fuse)
                {
                    full_product += " * ";
                }

                if (std::get<1>(_columns[f_col]))
                {
                    full_product += "!pin" + std::to_string(std::get<0>(_columns[f_col]));
                }
                else
                {
                    full_product += "pin" + std::to_string(std::get<0>(_columns[f_col]));
                }

                first_fuse = false;
            }
            full_product +=")";
        }

        // if XOR is not set, then the whole product is negated
        if (!_jedec.get_fuse_bit(std::get<0>(_olmc_configs[olmc_num])))
        {
            full_product += " }";
        }

        std::cout << "GAL16V8 olmc=" << olmc_num << ", product " << full_product << std::endl;
    }
};


int main(int argc, char* argv[])
{

    if (argc < 2)
    {
        std::cerr << "JED file missing" << std::endl;
        return -1;
    }

    std::ifstream jedec(argv[1], std::ios_base::binary);

    /// locate STX
    char x = 0;
    do
    {
        x = jedec.get();
        std::cout << "Probed " << static_cast<int>(x) << std::endl;
    }
    while(jedec && x != 0x02);
    if (!jedec)
    {
        std::cerr << "STX not found" << std::endl;
        return -1;
    }

    Jedec main_jedec;
    do
    {
        main_jedec.add_info_from_block(jedec);
        if (!jedec)
        {
            std::cout << " reached the eof" << std::endl;
        }
    }
    while(jedec);


    GAL16V8 gal(main_jedec);

    

    return 0;
}