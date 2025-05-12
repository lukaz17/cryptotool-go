// Copyright (C) 2025 Nguyen Nhat Tung
//
// CryptoTool is licensed under the MIT license.
// You should receive a copy of MIT along with this software.
// If not, see <https://opensource.org/license/mit>

package engine

import (
	"errors"

	"github.com/lukaz17/cryptotool-go/keymngr"
	"github.com/lukaz17/cryptotool-go/storage"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/tforce-io/tf-golib/stdx/stringxt"
	"github.com/tyler-smith/go-bip39"
)

// Struct KeygenModule handles user requests related HDAccounts key file
// generation and modification.
type KeygenModule struct {
	Logger zerolog.Logger
}

func NewKeygenModule(logger zerolog.Logger, cmdNane string) *KeygenModule {
	return &KeygenModule{
		Logger: logger.With().Str("module", "Keygen").Str("command", cmdNane).Logger(),
	}
}

// Read a key file and derive new account from mnemonic in the file and specified
// derivationPath, then save it.
func (m *KeygenModule) Add(keyFilePath, derivationPath string) error {
	multiAcc, err := m.readHDAccounts(keyFilePath)
	if err != nil {
		return err
	}

	if stringxt.IsEmptyOrWhitespace(multiAcc.Mnemonic) {
		return errors.New("mnemonic is not available")
	}
	if !bip39.IsMnemonicValid(multiAcc.Mnemonic) {
		return errors.New("invalid mnemonic")
	}

	hdAccount, err := m.updateHDAccount(multiAcc, derivationPath)
	if err != nil {
		return err
	}

	err = m.writeHDAccounts(multiAcc, keyFilePath)
	if err != nil {
		return err
	}

	m.Logger.Info().
		Str("address", hdAccount.AddressStr).
		Str("keyFile", keyFilePath).
		Msg("New account has been added to key file.")
	return nil
}

// Generate a number of random key files and save them to outputPath.
// If predicate is provided, the function will try to grind for vanity address instead.
func (m *KeygenModule) New(outputPath, derivationPath string, randomness, keyCount uint16, predicate *stringxt.Predicate) error {
	keyCounter := uint16(0)
	retryCounter := uint64(0)

	if randomness < 128 || randomness > 256 || randomness%32 != 0 {
		return errors.New("invalid entropy, valid values are 128, 160, 192, 224, 256")
	}
	for keyCounter < keyCount {
		mnemonic, entropy, err := keymngr.NewMnemonic2(int(randomness))
		if err != nil {
			return err
		}
		multiAcc := &storage.HDAccounts{
			Mnemonic:         mnemonic,
			Entropy:          entropy,
			EthereumAccounts: make(map[string]*storage.HDAccount),
		}
		hdAccount, err := m.updateHDAccount(multiAcc, derivationPath)
		if err != nil {
			return err
		}
		found, err := predicate.Match(hdAccount.AddressStr)
		if err != nil {
			return err
		}
		if found {
			keyCounter++
			keyFilePath := storage.FilePath(outputPath, hdAccount.AddressStr+".json")
			err = m.writeHDAccounts(multiAcc, keyFilePath)
			if err != nil {
				return err
			}
			m.Logger.Info().
				Str("address", hdAccount.AddressStr).
				Uint16("keyCountCount", keyCounter).
				Str("keyFile", keyFilePath).
				Uint64("retryCount", retryCounter).
				Msg("Found a new key.")
		}
		retryCounter++
		if retryCounter%1000 == 0 {
			m.Logger.Info().
				Uint16("keyCount", keyCounter).
				Uint64("retryCount", retryCounter).
				Msg("Finding key in progress...")
		}
	}

	m.Logger.Info().
		Uint16("keyCount", keyCounter).
		Uint64("retryCount", retryCounter).
		Msgf("Finished finding key.")
	return nil
}

// Read a key file and regenerate all accounts inside.
func (m *KeygenModule) Refresh(keyFilePath string) error {
	multiAcc, err := m.readHDAccounts(keyFilePath)
	if err != nil {
		return err
	}

	if stringxt.IsEmptyOrWhitespace(multiAcc.Mnemonic) {
		return errors.New("mnemonic is not available")
	}
	if !bip39.IsMnemonicValid(multiAcc.Mnemonic) {
		return errors.New("invalid mnemonic")
	}

	if multiAcc.EthereumAccounts != nil {
		for derivationPath := range multiAcc.EthereumAccounts {
			_, err = m.updateHDAccount(multiAcc, derivationPath)
			if err != nil {
				return err
			}
		}
	}

	err = m.writeHDAccounts(multiAcc, keyFilePath)
	if err != nil {
		return err
	}

	m.Logger.Info().
		Str("keyFile", keyFilePath).
		Msg("Key file has ben refreshed.")
	return nil
}

func (m *KeygenModule) logError(err error) {
	if err != nil {
		m.Logger.Err(err).Msgf("Unexpected error has occur. Program will exit.")
	}
}

// Read HDAccounts from keyFilePath and deserialize it from JSON.
func (m *KeygenModule) readHDAccounts(keyFilePath string) (*storage.HDAccounts, error) {
	fileContent, err := storage.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}
	return storage.ParseHDAccountsJson([]byte(fileContent))
}

// Derive a HDAccount using specified derivationPath and save it to the HDAccounts.
func (m *KeygenModule) updateHDAccount(multiAcc *storage.HDAccounts, derivationPath string) (*storage.HDAccount, error) {
	newAccount, err := keymngr.DeriveEthereumAccountFromMnemonic(multiAcc.Mnemonic, "", derivationPath)
	if err != nil {
		return nil, err
	}
	hdAccount := NewHDAccountFromEthereumAccount(newAccount)
	multiAcc.EthereumAccounts[derivationPath] = NewHDAccountFromEthereumAccount(newAccount)
	return hdAccount, nil
}

// Serialize HDAccounts into JSON and save it to keyFilePath.
func (m *KeygenModule) writeHDAccounts(multiAcc *storage.HDAccounts, keyFilePath string) error {
	fileBuffer, err := storage.JsonMarshal(multiAcc)
	if err != nil {
		return err
	}
	return storage.WriteFile(keyFilePath, fileBuffer)
}

// Define Cobra Command for Keygen module.
func KeygenCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "keygen",
		Short: "HD Accounts generation and modification",
	}

	addCmd := &cobra.Command{
		Use:  "add <key file path>",
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			flags := ParseKeygenFlags(cmd)
			m := NewKeygenModule(log.Logger, "add")
			m.logError(m.Add(args[0], flags.DerivationPath))
		},
	}
	addCmd.Flags().StringP("ckd", "p", "", "Child key perivation path. Must start with 'm'.")
	rootCmd.AddCommand(addCmd)

	newCmd := &cobra.Command{
		Use:  "new <output path>",
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			flags := ParseKeygenFlags(cmd)
			m := NewKeygenModule(log.Logger, "new")
			predicate := &stringxt.Predicate{
				Prefix: flags.AccountPrefix,
				Suffix: flags.AccountSuffix,
				Regexp: flags.AccountRegexp,
			}
			m.logError(m.New(args[0], flags.DerivationPath, flags.Entropy, flags.KeyCount, predicate))
		},
	}
	newCmd.Flags().StringP("ckd", "p", "", "Child key perivation path. Must start with 'm'.")
	newCmd.Flags().Uint16P("count", "n", 1, "Number of accounts to search for.")
	newCmd.Flags().Uint16P("entropy", "e", 256, "Entropy size for generating mnemonic. Valid values are 128, 160, 192, 224, 256.")
	newCmd.Flags().String("prefix", "", "Prefix of the output address. Case sensitive.")
	newCmd.Flags().String("suffix", "", "Suffix of the output address. Case sensitive.")
	newCmd.Flags().String("regexp", "", "Regular expression to match the output address. Prefix and suffix flags will be ignored.")
	rootCmd.AddCommand(newCmd)

	refreshCmd := &cobra.Command{
		Use:  "refresh <key file path>",
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			m := NewKeygenModule(log.Logger, "refresh")
			m.logError(m.Refresh(args[0]))
		},
	}
	rootCmd.AddCommand(refreshCmd)

	return rootCmd
}

// Struct KeygenFlags contains all flags used by Keygen module.
type KeygenFlags struct {
	AccountPrefix  string
	AccountRegexp  string
	AccountSuffix  string
	DerivationPath string
	Entropy        uint16
	KeyCount       uint16
}

// Extract all flags from a Cobra Command.
func ParseKeygenFlags(cmd *cobra.Command) *KeygenFlags {
	ckd, _ := cmd.Flags().GetString("ckd")
	count, _ := cmd.Flags().GetUint16("count")
	entropy, _ := cmd.Flags().GetUint16("entropy")
	prefix, _ := cmd.Flags().GetString("prefix")
	regexp, _ := cmd.Flags().GetString("regexp")
	suffix, _ := cmd.Flags().GetString("suffix")

	return &KeygenFlags{
		AccountPrefix:  prefix,
		AccountRegexp:  regexp,
		AccountSuffix:  suffix,
		DerivationPath: ckd,
		Entropy:        entropy,
		KeyCount:       count,
	}
}
