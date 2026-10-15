#include "core/Version.h"

namespace dasa::core {

const char* Version::string() {
    static constexpr char s[] = "2.0.0";
    return s;
}

} // namespace dasa::core
