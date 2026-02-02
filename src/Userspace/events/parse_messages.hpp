#pragma once

#include "events/event.hpp"

#include <3rd_party/nlohmann/json.hpp>
#include <3rd_party/magic_enum/magic_enum.hpp>

#include <memory>

template <typename T>
constexpr std::string_view to_string(T e) noexcept
{
    return magic_enum::enum_name(e);
}

namespace owlsm::events
{
void to_json(nlohmann::json& j, const std::shared_ptr<Event>& ev);
void to_json(nlohmann::json& j, const std::shared_ptr<Error>& e);
}
