"use strict";

const command = document.getElementById("install-command");
command.textContent = "curl -fsSL " + location.origin + "/install.sh -o install.sh && sudo bash install.sh";

async function loadRelease() {
  const response = await fetch("/version.json", { cache: "no-store" });
  if (!response.ok) throw new Error("版本信息请求失败：" + response.status);
  const release = await response.json();
  if (release.schemaVersion !== 1) throw new Error("暂不支持此版本信息格式");
  document.getElementById("version").textContent = "v" + release.version;
  document.getElementById("download-version").textContent = "稳定版 " + release.version;
  document.getElementById("notes").textContent = release.notes;
  const table = document.getElementById("downloads");
  for (const [platform, label] of [["linux", "Linux · musl"], ["macos", "macOS"], ["win", "Windows"]]) {
    for (const arch of ["x64", "arm64"]) {
      const asset = release[platform][arch];
      const row = document.createElement("tr");
      for (const text of [label, arch, (asset.size / 1024 / 1024).toFixed(1) + " MB"]) {
        const cell = document.createElement("td");
        cell.textContent = text;
        row.append(cell);
      }
      const cell = document.createElement("td");
      const link = document.createElement("a");
      link.href = asset.url;
      link.textContent = "下载 ↗";
      link.title = "SHA256: " + asset.sha256;
      cell.append(link);
      row.append(cell);
      table.append(row);
    }
  }
  const history = document.getElementById("history");
  for (const version of release.versions) {
    const link = document.createElement("a");
    link.href = version.url;
    link.textContent = version.tag;
    history.append(link);
  }
  document.getElementById("status").textContent = "所有下载均提供 SHA256 校验。";
}

loadRelease().catch((error) => {
  document.getElementById("status").textContent = "暂时无法加载下载信息。" + error.message;
});
