/* -*- indent-tabs-mode: nil -*- */
#include "proto/serializer_base.h"

#include <ostream>
#include <string>

namespace serialization {

std::ostream& operator<<(std::ostream& stream, const SerializeResult& r) {
  switch (r) {
    case SerializeResult::OK:
      return stream << "OK";
    case SerializeResult::INVALID_ENTRY_TYPE:
      return stream << "INVALID_ENTRY_TYPE";
    case SerializeResult::EMPTY_CERTIFICATE:
      return stream << "EMPTY_CERTIFICATE";
    case SerializeResult::CERTIFICATE_TOO_LONG:
      return stream << "CERTIFICATE_TOO_LONG";
    case SerializeResult::CERTIFICATE_CHAIN_TOO_LONG:
      return stream << "CERTIFICATE_CHAIN_TOO_LONG";
    case SerializeResult::INVALID_HASH_ALGORITHM:
      return stream << "INVALID_HASH_ALGORITHM";
    case SerializeResult::INVALID_SIGNATURE_ALGORITHM:
      return stream << "INVALID_SIGNATURE_ALGORITHM";
    case SerializeResult::SIGNATURE_TOO_LONG:
      return stream << "SIGNATURE_TOO_LONG";
    case SerializeResult::INVALID_HASH_LENGTH:
      return stream << "INVALID_HASH_LENGTH";
    case SerializeResult::EMPTY_PRECERTIFICATE_CHAIN:
      return stream << "EMPTY_PRECERTIFICATE_CHAIN";
    case SerializeResult::UNSUPPORTED_VERSION:
      return stream << "UNSUPPORTED_VERSION";
    case SerializeResult::EXTENSIONS_TOO_LONG:
      return stream << "EXTENSIONS_TOO_LONG";
    case SerializeResult::INVALID_KEYID_LENGTH:
      return stream << "INVALID_KEYID_LENGTH";
    case SerializeResult::EMPTY_LIST:
      return stream << "EMPTY_LIST";
    case SerializeResult::EMPTY_ELEM_IN_LIST:
      return stream << "EMPTY_ELEM_IN_LIST";
    case SerializeResult::LIST_ELEM_TOO_LONG:
      return stream << "LIST_ELEM_TOO_LONG";
    case SerializeResult::LIST_TOO_LONG:
      return stream << "LIST_TOO_LONG";
    case SerializeResult::EXTENSIONS_NOT_ORDERED:
      return stream << "EXTENSIONS_NOT_ORDERED";
  }
  return stream << "<unknown>";
}


std::ostream& operator<<(std::ostream& stream, const DeserializeResult& r) {
  switch (r) {
    case DeserializeResult::OK:
      return stream << "OK";
    case DeserializeResult::INPUT_TOO_SHORT:
      return stream << "INPUT_TOO_SHORT";
    case DeserializeResult::INVALID_HASH_ALGORITHM:
      return stream << "INVALID_HASH_ALGORITHM";
    case DeserializeResult::INVALID_SIGNATURE_ALGORITHM:
      return stream << "INVALID_SIGNATURE_ALGORITHM";
    case DeserializeResult::INPUT_TOO_LONG:
      return stream << "INPUT_TOO_LONG";
    case DeserializeResult::UNSUPPORTED_VERSION:
      return stream << "UNSUPPORTED_VERSION";
    case DeserializeResult::INVALID_LIST_ENCODING:
      return stream << "INVALID_LIST_ENCODING";
    case DeserializeResult::EMPTY_LIST:
      return stream << "EMPTY_LIST";
    case DeserializeResult::EMPTY_ELEM_IN_LIST:
      return stream << "EMPTY_ELEM_IN_LIST";
    case DeserializeResult::UNKNOWN_LEAF_TYPE:
      return stream << "UNKNOWN_LEAF_TYPE";
    case DeserializeResult::UNKNOWN_LOGENTRY_TYPE:
      return stream << "UNKNOWN_LOGENTRY_TYPE";
    case DeserializeResult::EXTENSIONS_TOO_LONG:
      return stream << "EXTENSIONS_TOO_LONG";
    case DeserializeResult::EXTENSIONS_NOT_ORDERED:
      return stream << "EXTENSIONS_NOT_ORDERED";
  }
  return stream << "<unknown>";
}

void WriteFixedBytes(const std::string& in, std::string* output) {
  output->append(in);
}

}  // namespace serialization
