#pragma once

// Chimera 1.5.2's PNG encoder includes the old LovyanGFX header name.
// LovyanGFX 1.2.35 provides the same dependency as lgfx_miniz.h. Forward to
// the real header without modifying downloaded libraries or bypassing PNG code.
// platformio.ini exports this include/ directory to library compile paths.
#include <lgfx/utility/lgfx_miniz.h>
