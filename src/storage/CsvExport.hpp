#pragma once
#include "core/ArpRecord.hpp"
namespace arp
{
// Rows supplied by caller define scope; UI explicitly selects retained or displayed rows.
void exportCsv(const std::string& path, const std::vector<ArpRecord>& rows, bool overwrite = false);
} // namespace arp
