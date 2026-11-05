#include <lean/lean.h>
#include <re2/re2.h>
#include <string>
#include <vector>

static std::string quote(const re2::StringPiece &s) {
    std::string out = "\"";
    const char *hex = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c < 32) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
        else out += c;
    }
    return out + "\"";
}

extern "C" LEAN_EXPORT lean_obj_res casbin_regex(b_lean_obj_arg input, b_lean_obj_arg source, uint8_t capture) {
    try {
        re2::StringPiece text(lean_string_cstr(input), lean_string_size(input) - 1);
        re2::StringPiece pattern(lean_string_cstr(source), lean_string_size(source) - 1);
        RE2::Options options;
        options.set_log_errors(false);
        // Go regexp rejects RE2's byte-only escape, which can split UTF-8 code points.
        options.set_never_capture(!capture);
        RE2 regex(pattern, options);
        if (!regex.ok()) return lean_mk_string(("{\"error\":" + quote(regex.error()) + "}").c_str());
        std::vector<re2::StringPiece> groups(capture ? regex.NumberOfCapturingGroups() + 1 : 1);
        bool match = regex.Match(text, 0, text.size(), RE2::UNANCHORED, groups.data(), groups.size());
        std::string result = match ? "{\"match\":true,\"captures\":[" : "{\"match\":false,\"captures\":[";
        bool first = true;
        if (match && capture) for (const auto &item : regex.NamedCapturingGroups()) {
            if (!first) result += ',';
            first = false;
            result += '[' + quote(item.first) + ',' + quote(groups[item.second]) + ']';
        }
        result += "]}";
        return lean_mk_string(result.c_str());
    } catch (const std::exception &error) {
        return lean_mk_string(("{\"error\":" + quote(error.what()) + "}").c_str());
    }
}
