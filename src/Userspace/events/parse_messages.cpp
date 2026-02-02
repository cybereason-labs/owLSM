#include "events/parse_messages.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

NLOHMANN_JSON_SERIALIZE_ENUM(file_type, {
    {UNKNOWN_FILE_TYPE, "UNKNOWN_FILE_TYPE"},
    {DIRECTORY, "DIRECTORY"},
    {SYMLINK, "SYMLINK"},
    {BLOCK_DEVICE, "BLOCK_DEVICE"},
    {CHAR_DEVICE, "CHAR_DEVICE"},
    {REGULAR_FILE, "REGULAR_FILE"},
    {SOCKET, "SOCKET"},
    {FIFO, "FIFO"},
    {NO_FILE, "NO_FILE"},
})

namespace owlsm::config
{
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(owlsm::config::RuleMetadata, description)
}

namespace owlsm::events
{

std::string ipv4_to_string(uint32_t be_addr) 
{
    char buf[INET_ADDRSTRLEN] = {0};
    in_addr a{};
    a.s_addr = be_addr;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

std::string ipv6_to_string(const unsigned int bytes[4]) 
{
    char buf[INET6_ADDRSTRLEN] = {0};
    in6_addr a6{};
    std::memcpy(a6.s6_addr, bytes, sizeof(a6.s6_addr));
    inet_ntop(AF_INET6, &a6, buf, sizeof(buf));
    return buf;
}

void to_json(nlohmann::json& j, const Path& p) { j = p.value; }
void to_json(nlohmann::json& j, const CommandLine& c) { j = c.value; }
void to_json(nlohmann::json& j, const Filename& f) { j = f.value; }

void to_json(nlohmann::json& j, const StdioFileDescriptorsAtProcessCreation& s)
{
    j = nlohmann::json{{"stdin", s.stdin_fd}, {"stdout", s.stdout_fd}, {"stderr", s.stderr_fd}};
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Owner, uid, gid)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(File, inode, dev, path, owner, mode, type, suid, sgid, last_modified_seconds, nlink, filename)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Process, pid, ppid, ruid, rgid, euid, egid, suid, cgroup_id, start_time, ptrace_flags, file, cmd, stdio_file_descriptors_at_process_creation)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ChownEventData, file, requested_owner_uid, requested_owner_gid)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ChmodEventData, file, requested_mode)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ExecEventData, new_process)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ExitEventData, exit_code, signal)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(GenericFileEventData, file)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(RenameEventData, flags, source_file, destination_file)

void to_json(nlohmann::json& j, const ForkEventData&)
{
    j = nlohmann::json::object();
}

void to_json(nlohmann::json& j, const NetworkEventData& e)
{
    j = nlohmann::json{
        {"direction", to_string(e.direction)},
        {"protocol", e.protocol},
        {"ip_type", e.ip_type},
        {"source_port", e.source_port},
        {"destination_port", e.destination_port}
    };

    if (e.ip_type == AF_INET)
    {
        const auto& ipv4 = std::get<Ipv4Addresses>(e.addresses);
        j["addresses"] = {
            {"ipv4", {
                {"source_ip", ipv4_to_string(ipv4.source_ip)},
                {"destination_ip", ipv4_to_string(ipv4.destination_ip)}
            }}
        };
    }
    else
    {
        const auto& ipv6 = std::get<Ipv6Addresses>(e.addresses);
        j["addresses"] = {
            {"ipv6", {
                {"source_ip", ipv6_to_string(ipv6.source_ip)}, 
                {"destination_ip", ipv6_to_string(ipv6.destination_ip)}
            }}
        };
    }
}

void to_json(nlohmann::json& j, const Event& ev)
{
    j = nlohmann::json{
        {"id", ev.id},
        {"type", to_string(ev.type)},
        {"action", to_string(ev.action)},
        {"matched_rule_id", ev.matched_rule_id},
        {"matched_rule_metadata", ev.matched_rule_metadata},
        {"had_error", ev.had_error_while_handling},
        {"process", ev.process},
        {"parent_process", ev.parent_process},
        {"time", ev.time}
    };

    std::visit([&j](const auto& data) {
        j["data"] = data;
    }, ev.data);
}

void to_json(nlohmann::json& j, const Error& e)
{
    j = nlohmann::json{
        {"error_code", e.error_code},
        {"location", e.location},
        {"details", e.details}
    };
}

void to_json(nlohmann::json& j, const std::shared_ptr<Event>& ev)
{
    to_json(j, *ev);
}

void to_json(nlohmann::json& j, const std::shared_ptr<Error>& e)
{
    to_json(j, *e);
}

}
