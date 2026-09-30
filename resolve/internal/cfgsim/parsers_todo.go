package cfgsim

import "errors"

var errNotYet = errors.New("cfgsim: this vendor's reader arrives in a later task")

func ParseJunos(string) (Config, error) { return nil, errNotYet }
func ParseXR(string) (Config, error)    { return nil, errNotYet }
func ParseBIRD(string) (Config, error)  { return nil, errNotYet }
