// Copyright 2016 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <QDir>
#include <QLocale>
#include "citra_qt/configuration/configure_general.h"
#include "citra_qt/ui_settings.h"
#include "core/core.h"
#include "core/settings.h"
#include "ui_configure_general.h"

ConfigureGeneral::ConfigureGeneral(QWidget* parent)
    : QWidget(parent), ui(new Ui::ConfigureGeneral) {

    ui->setupUi(this);
    this->setConfiguration();

    ui->toggle_cpu_jit->setEnabled(!Core::System::GetInstance().IsPoweredOn());

    // locale stuff
    QString m_langPath = QApplication::applicationDirPath();
    m_langPath.append("/languages");
    QDir dir(m_langPath);
    QStringList fileNames = dir.entryList(QStringList("*.qm"));

    for (int i = 0; i < fileNames.size(); ++i) {
        // get locale extracted by filename
        QString locale;
        locale = fileNames[i];                    // "de.qm"
        locale.truncate(locale.lastIndexOf('.')); // "de"
        QString lang = locale.left(locale.indexOf('_'));
        ui->language_combobox->addItem(lang, locale);
    }
}

ConfigureGeneral::~ConfigureGeneral() {}

void ConfigureGeneral::setConfiguration() {
    ui->toggle_deepscan->setChecked(UISettings::values.gamedir_deepscan);
    ui->toggle_check_exit->setChecked(UISettings::values.confirm_before_closing);
    ui->toggle_cpu_jit->setChecked(Settings::values.use_cpu_jit);

    // The first item is "auto-select" with actual value -1, so plus one here will do the trick
    ui->region_combobox->setCurrentIndex(Settings::values.region_value + 1);
}

void ConfigureGeneral::applyConfiguration() {
    QString m_langPath = QApplication::applicationDirPath() + "/languages/" +
                         ui->language_combobox->currentData().toString() + ".qm";
    Settings::values.ui_language_path = m_langPath.toStdString();

    UISettings::values.gamedir_deepscan = ui->toggle_deepscan->isChecked();
    UISettings::values.confirm_before_closing = ui->toggle_check_exit->isChecked();
    Settings::values.region_value = ui->region_combobox->currentIndex() - 1;
    Settings::values.use_cpu_jit = ui->toggle_cpu_jit->isChecked();
    Settings::Apply();
}
