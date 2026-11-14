#pragma once

#include "winlin/core.hpp"

namespace winlin {
// Read only system manufacturer/model from SMBIOS, never serial numbers or machine identifiers.
// The caller owns the firmware bytes; malformed records cannot escape their bounded buffer.
inline std::pair<std::string, std::string> smbios_system(std::string_view table) {
    while (table.size() >= 4) {
        const auto type = static_cast<unsigned char>(table[0]);
        const auto length = static_cast<unsigned char>(table[1]);
        if (length < 4 || length > table.size()) {
            break;
        }
        const auto end = table.find(std::string_view("\0\0", 2), length);
        if (end == std::string_view::npos) {
            break;
        }
        if (type == 1 && length >= 6) {
            const auto strings = table.substr(length, end - length + 1);
            auto field = [&](unsigned index) -> std::string {
                std::size_t offset{};
                for (unsigned current = 1; index && offset < strings.size(); ++current) {
                    const auto next = strings.find('\0', offset);
                    if (next == std::string_view::npos) {
                        break;
                    }
                    if (current == index) {
                        return std::string(strings.substr(offset, next - offset));
                    }
                    offset = next + 1;
                }
                return {};
            };
            return {field(static_cast<unsigned char>(table[4])),
                    field(static_cast<unsigned char>(table[5]))};
        }
        if (type == 127) {
            break;
        }
        table.remove_prefix(end + 2);
    }
    throw std::runtime_error("System manufacturer/model unavailable in SMBIOS");
}

// Classify positive firmware evidence, not the mere absence of a hypervisor marker.
// Unrecognized firmware remains unknown; Microsoft virtual firmware alone does not prove Azure.
inline Json describe_machine(const std::string& manufacturer, const std::string& model) {
    const auto vendor = lower(manufacturer);
    const auto product = lower(model);
    const bool aws_sku = vendor == "amazon ec2" && product.find('.') != std::string::npos &&
                         std::all_of(model.begin(), model.end(), [](unsigned char ch) {
                             return std::isalnum(ch) || ch == '.' || ch == '-';
                         });
    std::string type = "unknown";
    if (product.find("virtual") != std::string::npos ||
        vendor.find("vmware") != std::string::npos || vendor.find("qemu") != std::string::npos ||
        product.find("kvm") != std::string::npos || vendor.find("xen") != std::string::npos ||
        vendor == "google") {
        type = "virtual_machine";
    } else if (vendor == "amazon ec2") {
        type = !aws_sku                                      ? "unknown"
               : product.find(".metal") != std::string::npos ? "bare_metal"
                                                             : "virtual_machine";
    } else if (!model.empty() &&
               (vendor.starts_with("dell") || vendor == "hpe" || vendor == "hp" ||
                vendor == "hewlett-packard" || vendor.starts_with("lenovo") ||
                vendor.starts_with("supermicro") || vendor.starts_with("fujitsu"))) {
        type = "bare_metal";
    }
    return {{"type", type},
            {"manufacturer", manufacturer.empty() ? Json(nullptr) : Json(manufacturer)},
            {"model", model.empty() ? Json(nullptr) : Json(model)},
            {"cloud_provider", vendor == "amazon ec2" ? Json("AWS") : Json(nullptr)},
            {"vm_sku", aws_sku ? Json(model) : Json(nullptr)},
            {"detection_source", "SMBIOS manufacturer/model (best effort)"},
            {"unavailable_reason",
             type == "unknown"
                 ? Json("Firmware does not establish physical or virtual machine type")
             : type == "virtual_machine" && !aws_sku ? Json("VM SKU is not exposed by firmware")
                                                     : Json(nullptr)}};
}

// Accept only a bounded SKU returned by Azure's vmSize leaf, never full instance metadata.
inline void apply_azure_sku(Json& machine, std::string sku) {
    while (!sku.empty() && std::isspace(static_cast<unsigned char>(sku.back()))) {
        sku.pop_back();
    }
    if (sku.empty() || sku.size() > 128 ||
        !std::all_of(sku.begin(), sku.end(), [](unsigned char ch) {
            return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.';
        })) {
        throw std::runtime_error("Azure metadata did not return a valid VM SKU");
    }
    machine["type"] = "virtual_machine";
    machine["cloud_provider"] = "Azure";
    machine["vm_sku"] = std::move(sku);
    machine["detection_source"] = "SMBIOS and Azure IMDS vmSize";
    machine["unavailable_reason"] = nullptr;
}
}
