// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/cobra"
	"github.com/veraison/ccatoken"
	ccatoken_platform "github.com/veraison/ccatoken/platform"
	"github.com/veraison/corim/comid"
	"github.com/veraison/eat"
	"github.com/veraison/psatoken"
)

var (
	genCorimAttestationScheme *string
	genCorimEvidenceFile      *string
	genCorimKeyFile           *string
	genCorimCorimFile         *string
	genCorimTemplateDir       *string
)

var rootCmd = NewRootCmd()

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-corim <scheme> <evidence-file> <key-file>",
		Short: "generate CoRIM from supplied evidence",
		Long: `generate CoRIM from supplied evidence
		
		Generate CoRIM from evidence token (evidence.cbor), attestation scheme to use (only schemes supported 
		by ths tool are psa and cca), key material needed to verify the evidence (key.json) and templates
		supplied in the template directory. 
		Save it to the current working directory with default file name.

				gen-corim scheme evidence.cbor key.json \
						--template-dir=directory

		Generate CoRIM from evidence token (evidence.cbor), attestation scheme to use (only schemes supported 
		by ths tool are psa and cca), key material needed to verify the evidence (key.json) and templates
		supplied in the template directory.
		Save it as target file name (endorsements.cbor)

				gen-corim scheme evidence.cbor key.json \
						--template-dir=directory \
						--corim-file=endorsements.cbor

		Note: the CoMID and CoRIM templates within the template directory must be named comid-template.json
		and corim-template.json respectively
		`,
		Version: "0.0.1",
		Args:    cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			genCorimAttestationScheme = &args[0]
			genCorimEvidenceFile = &args[1]
			genCorimKeyFile = &args[2]
			if err := checkGenCorimArgs(); err != nil {
				return err
			}
			err := generate(genCorimAttestationScheme, genCorimEvidenceFile, genCorimKeyFile, genCorimCorimFile, genCorimTemplateDir)
			if err != nil {
				return err
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	genCorimCorimFile = cmd.Flags().StringP("corim-file", "c", "", "name of the generated CoRIM  file")

	genCorimTemplateDir = cmd.Flags().StringP("template-dir", "t", "templates", "path of directory containing the comid and corim templates")

	return cmd
}

// checkGenCorimArgs checks that the arguments are non-empty and that the relevent filepaths exist
func checkGenCorimArgs() error {

	if *genCorimAttestationScheme != "psa" && *genCorimAttestationScheme != "cca" {
		return fmt.Errorf("unsupported attestation scheme %s, only psa and cca are supported", *genCorimAttestationScheme)
	}

	// Validate evidence file with comprehensive security checks
	if err := validateEvidenceFile(*genCorimEvidenceFile); err != nil {
		return fmt.Errorf("evidence file validation failed: %w", err)
	}

	// Validate key file with comprehensive security checks
	if err := validateKeyFile(*genCorimKeyFile); err != nil {
		return fmt.Errorf("key file validation failed: %w", err)
	}

	// Validate template directory exists and is accessible
	if _, err := os.Stat(*genCorimTemplateDir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("template directory does not exist: %s", *genCorimTemplateDir)
		}
		return fmt.Errorf("cannot access template directory: %w", err)
	}

	// Check for required template files
	comidTemplatePath := filepath.Join(*genCorimTemplateDir, "comid-template.json")
	if err := validateInputFile(comidTemplatePath, "CoMID template file"); err != nil {
		return fmt.Errorf("CoMID template validation failed: %w", err)
	}

	corimTemplatePath := filepath.Join(*genCorimTemplateDir, "corim-template.json")
	if err := validateInputFile(corimTemplatePath, "CoRIM template file"); err != nil {
		return fmt.Errorf("CoRIM template validation failed: %w", err)
	}

	return nil
}

// validateInputFile performs comprehensive validation of input files with security checks
func validateInputFile(filePath, fileType string) error {
	if filePath == "" {
		return fmt.Errorf("%s path cannot be empty", fileType)
	}

	// Clean and validate path to prevent directory traversal attacks
	cleanPath := filepath.Clean(filePath)
	// Block suspicious patterns like multiple ../ or absolute paths with ..
	if strings.Contains(filePath, "../..") || (filepath.IsAbs(filePath) && strings.Contains(filePath, "..")) {
		return fmt.Errorf("%s path contains directory traversal patterns: %s", fileType, filePath)
	}

	// Check if file exists
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist: %s", fileType, filePath)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("permission denied accessing %s: %s", fileType, filePath)
		}
		return fmt.Errorf("error accessing %s: %w", fileType, err)
	}

	// Ensure it's a file, not a directory
	if fileInfo.IsDir() {
		return fmt.Errorf("%s path points to a directory, not a file: %s", fileType, filePath)
	}

	// Check file size limit (10MB maximum)
	const maxFileSize = 10 * 1024 * 1024
	if fileInfo.Size() > maxFileSize {
		return fmt.Errorf("%s is too large (%.2f MB). Maximum allowed size is %.2f MB", 
			fileType, float64(fileInfo.Size())/(1024*1024), float64(maxFileSize)/(1024*1024))
	}

	// Check if file is empty
	if fileInfo.Size() == 0 {
		return fmt.Errorf("%s is empty: %s", fileType, filePath)
	}

	// Check if file is readable
	file, err := os.Open(cleanPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", fileType, err)
	}
	defer file.Close()

	return nil
}

// validateEvidenceFile validates CBOR evidence files
func validateEvidenceFile(filePath string) error {
	if err := validateInputFile(filePath, "evidence file"); err != nil {
		return err
	}

	// Check file extension
	if !strings.HasSuffix(strings.ToLower(filePath), ".cbor") {
		return fmt.Errorf("evidence file must have .cbor extension: %s", filePath)
	}

	// Read first few bytes to validate CBOR format
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open evidence file for validation: %w", err)
	}
	defer file.Close()

	header := make([]byte, 4)
	n, err := file.Read(header)
	if err != nil {
		return fmt.Errorf("cannot read evidence file header: %w", err)
	}

	if n > 0 && !isValidCBORStart(header[:n]) {
		return fmt.Errorf("evidence file does not appear to be valid CBOR format: %s", filePath)
	}

	return nil
}

// validateKeyFile validates JSON Web Key files
func validateKeyFile(filePath string) error {
	if err := validateInputFile(filePath, "key file"); err != nil {
		return err
	}

	// Check file extension
	if !strings.HasSuffix(strings.ToLower(filePath), ".json") {
		return fmt.Errorf("key file must have .json extension: %s", filePath)
	}

	// Read and validate JSON structure
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read key file: %w", err)
	}

	// Validate JSON format
	var jsonData interface{}
	if err := json.Unmarshal(content, &jsonData); err != nil {
		return fmt.Errorf("key file contains invalid JSON: %w", err)
	}

	// Basic JWK validation - check for required fields
	var jwkData map[string]interface{}
	if err := json.Unmarshal(content, &jwkData); err != nil {
		return fmt.Errorf("key file is not a valid JSON object: %w", err)
	}

	// Check for essential JWK fields
	if _, hasKty := jwkData["kty"]; !hasKty {
		return fmt.Errorf("key file missing required 'kty' field for JWK format: %s", filePath)
	}

	return nil
}

// isValidCBORStart checks if the given bytes could be the start of a valid CBOR file
func isValidCBORStart(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Simple heuristic: check if it looks like text (which is definitely not CBOR)
	// Most CBOR files start with specific patterns
	firstByte := data[0]
	
	// If it starts with printable ASCII text, it's probably not CBOR
	if firstByte >= 0x20 && firstByte <= 0x7E {
		// Check if it looks like JSON or other text formats
		text := string(data)
		if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") || 
		   strings.HasPrefix(text, "This") || strings.HasPrefix(text, "Hello") {
			return false
		}
	}

	// CBOR major types (first 3 bits of first byte)
	majorType := firstByte >> 5

	// Valid CBOR major types are 0-7
	return majorType <= 7
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func generate(attestation_scheme *string, evidence_file *string, key_file *string, corim_file *string, template_dir *string) error {

	dir, err := CreateTemporaryDirectory()
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	//validate evidence cryptographically and write to a file
	evcli_cmd := exec.Command("evcli", *attestation_scheme, "check", "--token="+*evidence_file, "--key="+*key_file, "--claims="+dir+"/output-evidence-claims.json")
	if err = evcli_cmd.Run(); err != nil {
		return fmt.Errorf("error verifying evidence token: %w", err)
	}

	comidClaims, err := GetComidClaimsFromTemplate(*template_dir)
	if err != nil {
		return err
	}

	schemeClaims, err := GetSchemeClaimsFromEvidence(*attestation_scheme, *evidence_file)
	if err != nil {
		return err
	}

	measurements, err := GetMeasurementsFromComponents(schemeClaims, *attestation_scheme == "cca")
	if err != nil {
		return err
	}

	//creating a new reference value containing the measurements and the implementation ID from the evidence token
	class := comid.NewClassImplID(schemeClaims.implID)

	refVal := comid.ValueTriple{
		Environment:  comid.Environment{Class: class},
		Measurements: *measurements,
	}

	//replacing the reference values from the template with the created reference value
	comidClaims.Triples.ReferenceValues = comid.NewValueTriples()
	comidClaims.Triples.ReferenceValues.Add(&refVal)

	keys, err := CreateVerifKeysFromJWK(*key_file)
	if err != nil {
		return err
	}

	instance, err := comid.NewInstance(schemeClaims.instID, comid.UEIDType)
	if err != nil {
		return err
	}

	verifKey := comid.KeyTriple{
		Environment: comid.Environment{
			Class:    class,
			Instance: instance,
		},
		VerifKeys: keys,
	}

	comidClaims.Triples.AttestVerifKeys = nil
	comidClaims.AddAttestVerifKey(verifKey)

	err = CreateComidFromClaims(comidClaims, dir)
	if err != nil {
		return err
	}

	//creating a CoRIM from the CoMID and the provided template
	if *corim_file == "" {
		*corim_file = *attestation_scheme + "-endorsements.cbor"
	}

	corim_cmd := exec.Command("cocli", "corim", "create", "--template="+*template_dir+"/corim-template.json", "--comid="+dir+"/comid-claims.cbor", "--output="+*corim_file)

	if err := corim_cmd.Run(); err != nil {
		return fmt.Errorf("error thrown by cocli corim create: %w", err)
	}

	fmt.Println(`>> generated "` + *corim_file + `" using "` + *evidence_file + `"`)

	return nil
}

func convertJwkToPEM(fileName string) (pemKey string, err error) {
	var buf bytes.Buffer
	// fileName is the name of the file as string type where the JWK is stored
	keyJWK, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("error loading verifying key from %s: %w", fileName, err)
	}
	pkey, err := PubKeyFromJWK(keyJWK)
	if err != nil {
		return "", fmt.Errorf("error loading verifying key from %s: %w", fileName, err)
	}
	pubBytes2, err := x509.MarshalPKIXPublicKey(pkey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes2,
	}
	if err := pem.Encode(&buf, block); err != nil {
		return "", fmt.Errorf("failed to pem encode: %w", err)
	}
	keyStr := buf.String()
	return keyStr, nil
}

// PubKeyFromJWK extracts a crypto.PublicKey from the supplied JSON Web Key
func PubKeyFromJWK(rawJWK []byte) (crypto.PublicKey, error) {
	var pKey crypto.PublicKey
	err := jwk.ParseRawKey(rawJWK, &pKey)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return pKey, nil
}

// GenComidClaimsFromTemplate reads in the corim template structure and checks the validity
func GetComidClaimsFromTemplate(template_dir string) (*comid.Comid, error) {
	content, err := os.ReadFile(template_dir + "/comid-template.json")
	if err != nil {
		return nil, fmt.Errorf("error reading comid template: %w", err)
	}

	comidClaims := comid.NewComid()
	err = comidClaims.FromJSON(content)
	if err != nil {
		return nil, fmt.Errorf("error umarshalling comid template: %w", err)
	}

	err = comidClaims.Valid()
	if err != nil {
		return nil, fmt.Errorf("error validating comid template: %w", err)
	}

	return comidClaims, nil
}

// GetMeasurementsFromComponents creates a new measurements list to hold the measurements extracted from the evidence token
func GetMeasurementsFromComponents(schemeClaims *SchemeClaims, isCca bool) (*comid.Measurements, error) {
	measurements := comid.NewMeasurements()

	for _, component := range schemeClaims.swComponents {
		signerID, err := component.GetSignerID()
		if err != nil {
			return nil, err
		}
		refValID, err := comid.NewPSARefValID(signerID)
		if err != nil {
			return nil, err
		}
		measurementType, err := component.GetMeasurementType()
		if err == nil {
			refValID.SetLabel(measurementType)
		}
		version, err := component.GetVersion()
		if err == nil {
			refValID.SetVersion(version)
		}
		measurement, err := comid.NewPSAMeasurement(*refValID)
		if err != nil {
			return nil, err
		}
		measurementValue, err := component.GetMeasurementValue()
		if err != nil {
			return nil, err
		}
		measurement.AddDigest(1, measurementValue)
		measurements.Add(measurement)
	}

	//adding cca specific measurement
	if isCca {
		configID := comid.CCAPlatformConfigID("cfg v1.0.0")
		measurement, err := comid.NewCCAPlatCfgMeasurement(configID)
		if err != nil {
			return nil, err
		}
		measurement.SetRawValueBytes(schemeClaims.config, []byte{})
		measurements.Add(measurement)
	}

	return measurements, nil
}

// GetEvidenceClaims reads in the evidence token and extracts the claims
func GetSchemeClaimsFromEvidence(attestation_scheme string, evidence_file string) (*SchemeClaims, error) {
	content, err := os.ReadFile(evidence_file)
	if err != nil {
		return nil, fmt.Errorf("error reading the evidence token: %w", err)
	}

	var evidenceClaims psatoken.IClaims

	if attestation_scheme == "psa" {
		evidence, err := psatoken.DecodeAndValidateEvidenceFromCOSE(content)
		if err != nil {
			return nil, fmt.Errorf("error umarshalling evidence token: %w", err)
		}

		evidenceClaims = evidence.Claims
	} else {
		evidence, err := ccatoken.DecodeAndValidateEvidenceFromCBOR(content)
		if err != nil {
			return nil, fmt.Errorf("error umarshalling evidence token: %w", err)
		}

		evidenceClaims = evidence.PlatformClaims
	}

	swComponents, err := evidenceClaims.GetSoftwareComponents()
	if err != nil {
		return nil, fmt.Errorf("error extracting software components: %w", err)
	}

	implIDBytes, err := evidenceClaims.GetImplID()
	if err != nil {
		return nil, fmt.Errorf("error extracting implementation ID: %w", err)
	}
	var implID comid.ImplID
	copy(implID[:], implIDBytes)

	instID, err := evidenceClaims.GetInstID()
	if err != nil {
		return nil, fmt.Errorf("error extracting instance ID: %w", err)
	}
	var ueid eat.UEID = instID

	var config []byte
	if attestation_scheme == "cca" {
		config, err = evidenceClaims.(ccatoken_platform.IClaims).GetConfig()
		if err != nil {
			return nil, fmt.Errorf("error extracting configuration data: %w", err)
		}
	}

	return &SchemeClaims{
		swComponents: swComponents,
		implID:       implID,
		instID:       ueid,
		config:       config,
	}, nil
}

type SchemeClaims struct {
	swComponents []psatoken.ISwComponent
	implID       comid.ImplID
	instID       eat.UEID
	config       []byte
}

func CreateComidFromClaims(comidClaims *comid.Comid, dir string) error {
	//writing the constructed claims into a json file to be used as a CoMID template
	content, err := comidClaims.ToJSON()
	if err != nil {
		return fmt.Errorf("error marshalling claims: %w", err)
	}
	os.WriteFile(dir+"/comid-claims.json", content, 0664)

	//creating a CoMID from the constructed template
	comid_cmd := exec.Command("cocli", "comid", "create", "--template="+dir+"/comid-claims.json", "--output-dir="+dir)
	if err := comid_cmd.Run(); err != nil {
		return fmt.Errorf("error thrown by cocli comid create: %w", err)
	}

	return nil
}

// CreateTemporaryDirectory creates a temporary directory to store the intermediate files
func CreateTemporaryDirectory() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("error finding working directory: %w", err)
	}

	dir, err := os.MkdirTemp(wd, "gen-corim_data")
	if err != nil {
		return "", fmt.Errorf("error creating temporary directory: %w", err)
	}

	return dir, nil
}

// CreateVerifKeysFromJWK extracts the key data from the key file and uses it to overwrite the AttestVerifKeys triple
func CreateVerifKeysFromJWK(key_file string) (comid.CryptoKeys, error) {
	key_data, err := convertJwkToPEM(key_file)
	if err != nil {
		return nil, err
	}
	key, err := comid.NewPKIXBase64Key(key_data)
	if err != nil {
		return nil, err
	}
	keys := comid.NewCryptoKeys()
	keys.Add(key)
	return *keys, nil
}
