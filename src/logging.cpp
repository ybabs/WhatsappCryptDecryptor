//
// Created by daniel on 8/22/25.
//

#include "logging.h"
#include <mutex>
namespace logging
{

    static std::once_flag gInitOnce;


    void initLogging(plog::Severity level, const char* filename)
    {
        std::call_once(gInitOnce, [&]
        {
            plog::init(level, filename);
        });

    }

}