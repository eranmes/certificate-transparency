/* -*- mode: c++; indent-tabs-mode: nil -*- */
#ifndef SERIALIZER_V2_H
#define SERIALIZER_V2_H

#include <string>

#include <openssl/objects.h>

#include "proto/serializer.h"
#include "util/statusor.h"

// RFC6962-bis (V2) stuff.
namespace rfc6962_bis {
class OID {
 public:
  static util::StatusOr<OID> FromString(const std::string& oid_string);
  static util::StatusOr<OID> FromTagMissingDER(const std::string& der_oid);

  OID();
  OID(const OID& other);
  ~OID();

  util::StatusOr<std::string> ToTagMissingDER() const;
  std::string ToString() const;

 private:
  // Takes ownership
  OID(ASN1_OBJECT* oid);

  ASN1_OBJECT *oid_;
};

typedef google::protobuf::RepeatedPtrField<ct::SthExtension>
    repeated_sth_extension;
typedef google::protobuf::RepeatedPtrField<ct::SctExtension>
    repeated_sct_extension;

SerializeResult SerializeSCTV2ToTLS(const ct::SignedCertificateTimestampV2& sct);

DeserializeResult DeserializeMerkleTreeLeafV2(ct::MerkleTreeLeaf* leaf);

DeserializeResult DeserializeSCTV2(ct::SignedCertificateTimestamp* sct);

}  // namespace rfc6962_bis

#endif
