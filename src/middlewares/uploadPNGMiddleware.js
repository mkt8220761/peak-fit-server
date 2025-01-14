import multer from "multer";

const uploadPNG = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "image/png") {
      cb(null, true);
    } else {
      cb(new Error("Only PNG files are allowed!"), false);
    }
  },
});

export default uploadPNG;
