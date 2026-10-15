#include <QApplication>
#include <QCommandLineParser>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "app/MainWindow.h"
#include "app/ThemeManager.h"
#include "core/Version.h"

namespace {

void setupLogging() {
    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("dasa.log", /*truncate=*/false);
        auto logger = std::make_shared<spdlog::logger>(
            "dasa", spdlog::sinks_init_list{console_sink, file_sink});
        logger->set_level(spdlog::level::info);
        spdlog::set_default_logger(logger);
        spdlog::flush_on(spdlog::level::warn);
    } catch (const spdlog::spdlog_ex& ex) {
        // Logging failing to initialize shouldn't stop the app from
        // launching - fall back to spdlog's built-in default logger
        // (console-only) and keep going.
        std::fprintf(stderr, "Log init failed: %s\n", ex.what());
    }
}

} // namespace

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("DASA");
    QApplication::setApplicationDisplayName("Driver Attack Surface Analyzer");
    QApplication::setOrganizationName("DASA Project");
    QApplication::setApplicationVersion(dasa::core::Version::string());

    setupLogging();
    spdlog::info("DASA v{} starting", dasa::core::Version::string());

    dasa::app::ThemeManager::applyDarkTheme(app);

    QCommandLineParser parser;
    parser.setApplicationDescription("Windows kernel driver attack surface analysis platform");
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption driverOption(
        QStringList() << "driver",
        "Driver (.sys) file to load on startup.",
        "path");
    parser.addOption(driverOption);
    parser.process(app);

    dasa::app::MainWindow window;
    window.show();

    if (parser.isSet(driverOption)) {
        window.loadDriver(parser.value(driverOption));
    }

    const int rc = QApplication::exec();
    spdlog::info("DASA exiting with code {}", rc);
    return rc;
}
