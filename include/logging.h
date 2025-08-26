//
// Created by daniel on 8/22/25.
//

#pragma once

#include <plog/Log.h>
#include <plog/Initializers/RollingFileInitializer.h>

namespace logging
{
    void initLogging(plog::Severity level = plog::info, const char* filename = "decryptor.log");

}