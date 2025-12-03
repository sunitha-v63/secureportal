
const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");
const filePreview = document.getElementById("filePreview");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");
const removeBtn = document.getElementById("removeFileBtn");


["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
    document.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
    });
});

if (dropZone) {

    dropZone.addEventListener("dragover", () => {
        dropZone.classList.add("drag-active");
    });

    dropZone.addEventListener("dragleave", () => {
        dropZone.classList.remove("drag-active");
    });
}

if (dropZone) {
    dropZone.addEventListener("drop", (e) => {

        dropZone.classList.remove("drag-active");

        const files = e.dataTransfer.files;
        if (!files.length) return;

        const dt = new DataTransfer();
        dt.items.add(files[0]);
        fileInput.files = dt.files;

        fileInput.dispatchEvent(new Event("change"));
    });
}

fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) {
        filePreview.style.display = "none";
        return;
    }

    filePreview.style.display = "block";
    fileName.innerText = "Name: " + file.name;
    fileSize.innerText = "Size: " + (file.size / 1024 / 1024).toFixed(2) + " MB";
});

removeBtn.addEventListener("click", () => {
    fileInput.value = "";
    filePreview.style.display = "none";
});
