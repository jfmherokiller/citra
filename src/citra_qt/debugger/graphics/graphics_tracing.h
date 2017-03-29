// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include "citra_qt/debugger/graphics/graphics_breakpoint_observer.h"

class EmuThread;

class GraphicsTracingWidget : public BreakPointObserverDock {
    Q_OBJECT

public:
    explicit GraphicsTracingWidget(std::shared_ptr<Pica::DebugContext> debug_context,
                                   QWidget* parent = nullptr);

    void OnEmulationStarting(EmuThread* emu_thread);
    void OnEmulationStopping();

private slots:
    void StartRecording();
    void StopRecording();
    void AbortRecording();

    void OnBreakPointHit(Pica::DebugContext::Event event, void* data) override;
    void OnResumed() override;

signals:
    void SetStartTracingButtonEnabled(bool enable);
    void SetStopTracingButtonEnabled(bool enable);
    void SetAbortTracingButtonEnabled(bool enable);
};
