// Layar "Cari Memori": pencari nilai/alamat + preset widescreen, hasilnya bisa jadi cheat CWCheat.
#pragma once

#include <string>

#include "Common/UI/View.h"
#include "Common/UI/UIScreen.h"
#include "Common/UI/Context.h"
#include "UI/BaseScreens.h"
#include "UI/SimpleDialogScreen.h"
#include "UI/MiscViews.h"

class MemScanScreen : public UITwoPaneBaseDialogScreen {
public:
	MemScanScreen(const Path &gamePath, const std::string &gameID);

	const char *tag() const override { return "MemScan"; }

protected:
	void CreateSettingsViews(UI::ViewGroup *) override;
	void CreateContentViews(UI::ViewGroup *) override;
	std::string_view GetTitle() const override { return "Cari Memori"; }

private:
	bool SaveCheat(const std::string &name);

	std::string gameID_;
};
