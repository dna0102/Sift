package ui

import (
	"net/http"
	"strconv"
)

func (u *UI) emuStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, u.app.Emulator.Status())
}

func (u *UI) emuDevices(w http.ResponseWriter, r *http.Request) {
	avds, running := u.app.Emulator.ListDevices()

	frida := u.app.Emulator.FridaProbe("")
	writeJSON(w, map[string]any{"avds": avds, "running": running, "available": u.app.Emulator.Available(),
		"fridaPython": frida.Python, "fridaReason": frida.Reason})
}

func (u *UI) emuLaunch(w http.ResponseWriter, r *http.Request) {
	if !u.app.Emulator.Available() {
		http.Error(w, u.app.Emulator.Status().Reason, http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("report"), 10, 64)
	rep := u.app.Mobile.Get(id)
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
	if err := u.app.Emulator.Launch(avd, rep, unpin); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, u.app.Emulator.Status())
}

func (u *UI) emuStop(w http.ResponseWriter, r *http.Request) {
	u.app.Emulator.Stop()
	writeJSON(w, u.app.Emulator.Status())
}
