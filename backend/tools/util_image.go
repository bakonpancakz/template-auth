package tools

import (
	"bytes"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math"
	"net/http"
	"path"
	"strconv"

	"golang.org/x/image/draw"
	"golang.org/x/image/webp"
)

// NOTE: For performance order your formats from largest to smallest as the
// previous resize is used to improve performance. (Less Pixels = Less Work!)

type imageOptions struct {
	Folder  string
	Formats []imageFormat
}

type imageFormat struct {
	Name   string
	Height int
	Width  int
}

var (
	ImageContentType    = "image/jpeg"
	ErrImageMalformed   = errors.New("malformed image data")
	ErrImageUnsupported = errors.New("unsupported image format")
	ImageOptionsIcons   = imageOptions{
		Folder: "icons",
		Formats: []imageFormat{
			{Name: "md.jpeg", Height: 128, Width: 128},
		},
	}
	ImageOptionsAvatars = imageOptions{
		Folder: "avatars",
		Formats: []imageFormat{
			{Name: "lg.jpeg", Height: 256, Width: 256},
			{Name: "md.jpeg", Height: 128, Width: 128},
			{Name: "sm.jpeg", Height: 64, Width: 64},
		},
	}
	ImageOptionsBanners = imageOptions{
		Folder: "banners",
		Formats: []imageFormat{
			{Name: "md.jpeg", Height: 200, Width: 600},
			{Name: "sm.jpeg", Height: 100, Width: 300},
		},
	}
	ImageOptions = map[string]imageOptions{
		ImageOptionsIcons.Folder:   ImageOptionsIcons,
		ImageOptionsAvatars.Folder: ImageOptionsAvatars,
		ImageOptionsBanners.Folder: ImageOptionsBanners,
	}
)

// Return Paths for Images that would be generated using the given options
func ImagePaths(o imageOptions, id int64, hash string) []string {
	paths := make([]string, 0, len(o.Formats))
	for _, f := range o.Formats {
		paths = append(paths, path.Join(o.Folder, strconv.FormatInt(id, 10), hash, f.Name))
	}
	return paths
}

// Helper Function that calls ImageProcessor to handle the given image, it aborts the request
// with the appropriate API Error in case of failure. You should return early if false is returned.
func ImageHandler(w http.ResponseWriter, r *http.Request, o imageOptions, id int64, d []byte) (bool, string) {
	hash, err := ImageProcessor(o, id, d)
	if errors.Is(err, ErrImageUnsupported) {
		SendClientError(w, r, ERROR_IMAGE_UNSUPPORTED)
		return false, hash
	}
	if errors.Is(err, ErrImageMalformed) {
		SendClientError(w, r, ERROR_IMAGE_MALFORMED)
		return false, hash
	}
	if err != nil {
		SendServerError(w, r, err)
		return false, hash
	}
	return true, hash
}

// All-In-One Function that resizes an image into multiple formats and stores them,
// returning a unique hash intended to be stored in the database.
func ImageProcessor(o imageOptions, id int64, d []byte) (string, error) {

	// Decode Image with the appropriate decoder based on it's starting bytes
	// https://en.wikipedia.org/wiki/Magic_number_(programming)#Magic_numbers_in_files)
	var (
		decoderImage image.Image
		decoderError error
	)
	switch {
	case len(d) > 3 && // JPEG
		d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF:
		decoderImage, decoderError = jpeg.Decode(bytes.NewReader(d))

	case len(d) > 8 && // PNG
		d[0] == 0x89 && d[1] == 0x50 && d[2] == 0x4E && d[3] == 0x47 &&
		d[4] == 0x0D && d[5] == 0x0A && d[6] == 0x1A && d[7] == 0x0A:
		decoderImage, decoderError = png.Decode(bytes.NewReader(d))

	case len(d) > 4 && // GIF
		d[0] == 0x47 && d[1] == 0x49 && d[2] == 0x46 && d[3] == 0x38:
		decoderImage, decoderError = gif.Decode(bytes.NewReader(d))

	case len(d) > 12 && // WEBP
		d[0] == 0x52 && d[1] == 0x49 && d[2] == 0x46 && d[3] == 0x46 &&
		d[8] == 0x57 && d[9] == 0x45 && d[10] == 0x42 && d[11] == 0x50:
		decoderImage, decoderError = webp.Decode(bytes.NewReader(d))

	default:
		return "", ErrImageUnsupported
	}
	if decoderError != nil {
		return "", ErrImageMalformed
	}

	// Processing and Upload Formats
	ctx, cancel := NewContext()
	defer cancel()

	imageHash := GenerateImageHash(d)
	for _, f := range o.Formats {

		// Calculate Scaled Height and Width
		bounds := decoderImage.Bounds()
		iw, ih := bounds.Dx(), bounds.Dy()
		sx := float64(f.Width) / float64(iw)
		sy := float64(f.Height) / float64(ih)

		scale := math.Max(sx, sy)
		sw := int(float64(iw) * scale)
		sh := int(float64(ih) * scale)

		// Resize Image
		scaled := image.NewRGBA(image.Rect(0, 0, sw, sh))
		draw.CatmullRom.Scale(scaled, scaled.Bounds(), decoderImage, bounds, draw.Over, nil)

		// Crop Image
		offsetX := (sw - f.Width) / 2
		offsetY := (sh - f.Height) / 2
		cropped := image.NewRGBA(image.Rect(0, 0, f.Width, f.Height))
		draw.Draw(cropped, cropped.Bounds(), scaled, image.Pt(offsetX, offsetY), draw.Over)
		decoderImage = cropped // speeds up next resize

		// Encode Image
		output := bytes.Buffer{}
		path := path.Join(o.Folder, strconv.FormatInt(id, 10), imageHash, f.Name)
		if err := jpeg.Encode(&output, cropped, &jpeg.Options{Quality: 100}); err != nil {
			return imageHash, err
		}
		if err := Storage.Put(ctx, path, ImageContentType, output.Bytes()); err != nil {
			return imageHash, err
		}
	}

	return imageHash, nil
}
