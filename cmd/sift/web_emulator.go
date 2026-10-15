package main

import (
	"net/http"
	"strconv"
)

// HTTP handlers for the emulator: list devices, launch an APK in an emulator, stop it, and
// report status. The dashboard polls status over the existing apps SSE stream.

func (u *UI) emuStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, u.app.emulator.Status())
}

func (u *UI) emuDevices(w http.ResponseWriter, r *http.Request) {
	avds, running := u.app.emulator.ListDevices()
	// Frida (for SSL unpinning) needs the python frida module on the host. The device-side
	// frida-server is checked at launch time against the chosen device.
	frida := u.app.emulator.fridaProbe("")
	writeJSON(w, map[string]any{"avds": avds, "running": running, "available": u.app.emulator.Available(),
		"fridaPython": frida.Python, "fridaReason": frida.Reason})
}

func (u *UI) emuLaunch(w http.ResponseWriter, r *http.Request) {
	if !u.app.emulator.Available() {
		http.Error(w, u.app.emulator.Status().Reason, http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("report"), 10, 64)
	rep := u.app.mobile.Get(id)
	if rep == nil {
		http.Error(w, "No such report", http.StatusNotFound)
		return
	}
	if rep.Kind != "apk" {
		http.Error(w, "Only Android apps (.apk) can be run in the emulator.", http.StatusBadRequest)
		return
	}
	avd := r.FormValue("avd")
	if avd == "" {
		http.Error(w, "Choose a device.", http.StatusBadRequest)
		return
	}
	unpin := r.FormValue("unpin") == "1"
	if err := u.app.emulator.Launch(avd, rep, unpin); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, u.app.emulator.Status())
}

func (u *UI) emuStop(w http.ResponseWriter, r *http.Request) {
	u.app.emulator.Stop()
	writeJSON(w, u.app.emulator.Status())
}
