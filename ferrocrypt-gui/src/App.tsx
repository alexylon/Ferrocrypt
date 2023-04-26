import {useEffect, useState} from "react";
import {invoke} from "@tauri-apps/api/tauri";
import {listen} from '@tauri-apps/api/event'
import {open} from "@tauri-apps/api/dialog";
import "./App.css";

interface AppState {
    disableLargeFilesCheckbox: boolean;
    disableStart: boolean;
    hidePassword: boolean;
    inpath: string;
    isLargeFile: boolean;
    keypath: string;
    matchingIcon: string;
    mode: string;
    outpath: string;
    password: string;
    passwordMatch: boolean;
    passwordRepeated: string;
    passwordType: string;
    requirePassword: boolean;
    requirePasswordRepeated: boolean;
    showMatchingIcon: boolean;
    showVisibilityIcon: boolean;
    statusErr: string;
    statusOk: string;
    visibilityIcon: string;
}

const initialState: AppState = {
    disableLargeFilesCheckbox: false,
    disableStart: true,
    hidePassword: true,
    inpath: "",
    isLargeFile: false,
    keypath: "",
    matchingIcon: "/icon-dot-red-30.png",
    mode: "se",
    outpath: "",
    password: "",
    passwordMatch: false,
    passwordRepeated: "",
    passwordType: "password",
    requirePassword: true,
    requirePasswordRepeated: true,
    showMatchingIcon: false,
    showVisibilityIcon: true,
    statusErr: "",
    statusOk: "Ready",
    visibilityIcon: "/icon-unhide-50.png"
};

function App() {
    const [state, setState] = useState(initialState);

    const updateState = (stateChanges: Partial<AppState>) => {
        setState(prevState => ({
            ...prevState,
            ...stateChanges,
        }));
    };

    listen('tauri://file-drop', (event: any) => {
        let inputPath = event.payload[0];
        let inputDirPath = inputPath.replace(/[/\\][^/\\]*$/, '');

        updateState({
            inpath: inputPath,
            outpath: inputDirPath,
        });
    }).then();

    useEffect(() => {
        const {hidePassword, inpath, password, passwordRepeated, requirePasswordRepeated, keypath} = state;

        // Modes:
        // se == symmetric encryption, sd == symmetric decryption, he == hybrid encryption, hd == hybrid decryption, gk == generate key pair

        const fileExtension = inpath.slice(inpath.lastIndexOf("."));

        if (fileExtension === ".fcs") {
            updateState({mode: "sd"})
        } else if (fileExtension === ".fch") {
            updateState({mode: "hd"})
        }

        switch (mode) {
            case "se": { // Symmetric encryption mode
                updateState({
                    disableLargeFilesCheckbox: false,
                    disableStart: inpath === "" || password.length < 1 || (password !== passwordRepeated && requirePasswordRepeated),
                    matchingIcon: hidePassword && !!passwordRepeated && password === passwordRepeated
                        ? "/icon-dot-green-30.png"
                        : "/icon-dot-red-30.png",
                    requirePassword: true,
                    requirePasswordRepeated: hidePassword,
                    passwordType: hidePassword ? "password" : "text",
                    showMatchingIcon: hidePassword ? !!passwordRepeated : false,
                    showVisibilityIcon: true,
                    visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png",
                });
            }
                break;
            case "sd": { // Symmetric decryption mode
                updateState({
                    disableLargeFilesCheckbox: true,
                    disableStart: inpath === "" || password.length < 1,
                    passwordType: hidePassword ? "password" : "text",
                    requirePassword: true,
                    requirePasswordRepeated: false,
                    showMatchingIcon: false,
                    showVisibilityIcon: true,
                    visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png",
                });
            }
                break;
            case "he": { // Hybrid encryption mode
                updateState({
                    disableLargeFilesCheckbox: false,
                    disableStart: inpath === "" || keypath === "",
                    passwordType: hidePassword ? "password" : "text",
                    requirePassword: false,
                    requirePasswordRepeated: false,
                    showMatchingIcon: false,
                    showVisibilityIcon: false,
                });
            }
                break;
            case "hd": { // Hybrid decryption mode
                updateState({
                    disableLargeFilesCheckbox: true,
                    disableStart: inpath === "" || password.length < 1 || keypath === "",
                    passwordType: hidePassword ? "password" : "text",
                    requirePasswordRepeated: false,
                    showMatchingIcon: false,
                    showVisibilityIcon: true,
                    visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png"
                });
            }
                break;
            case "gk": { // Generate key pair mode
                updateState({
                    disableLargeFilesCheckbox: true,
                    disableStart: outpath === "" || password.length < 1 || (password !== passwordRepeated && requirePasswordRepeated),
                    matchingIcon: hidePassword && !!passwordRepeated && password === passwordRepeated
                        ? "/icon-dot-green-30.png"
                        : "/icon-dot-red-30.png",
                    passwordType: hidePassword ? "password" : "text",
                    requirePassword: true,
                    requirePasswordRepeated: hidePassword,
                    showMatchingIcon: hidePassword ? !!passwordRepeated : false,
                    showVisibilityIcon: true,
                    visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png",
                });
            }
        }
    }, [
        state.hidePassword,
        state.inpath,
        state.keypath,
        state.mode,
        state.password,
        state.passwordRepeated,
        state.requirePassword,
        state.requirePasswordRepeated,
    ]);


    const handleSelectKey = async () => {
        const selected = await open({
            multiple: false,
            directory: false
        }) as string;

        updateState({
            keypath: selected
        });
    };

    const handleSelectOutputDir = async () => {
        const selected = await open({
            multiple: false,
            directory: true
        }) as string;

        updateState({
            outpath: selected
        });
    };

    const handlePasswordChange = (value: string) => {
        updateState({
            password: value
        });
    }

    const handleRepeatedPasswordChange = (value: string) => {
        updateState({
            passwordRepeated: value
        });
    }

    const handleLargeFileSupport = () => {
        updateState({
            isLargeFile: !state.isLargeFile
        });
    }

    const handleSymmetricEncryptionMode = () => {
        updateState({
            mode: "se"
        });
    }

    const handleHybridEncryptionMode = () => {
        updateState({
            mode: "he"
        });
    }

    const handleGenerateKeyPairMode = () => {
        updateState({
            mode: "gk"
        });
    }

    const handlePasswordHide = () => {
        updateState({
            hidePassword: !state.hidePassword
        });
    }

    const handleStart = async () => {
        updateState({
            statusOk: "Working ...",
            statusErr: "",
        });

        const {inpath, outpath, password, isLargeFile, keypath, mode} = state;
        await invoke("start", {
            inpath,
            outpath,
            password,
            isLargeFile,
            keypath,
            mode
        })
            // @ts-ignore
            .then((message: string) => {
                updateState({
                    statusOk: message,
                    statusErr: "",
                });
            })
            .catch((error: string) => {
                updateState({
                    statusOk: "",
                    statusErr: error.replace(/"+/g, ''),
                });
            });
    }

    const handleClear = () => setState(initialState);

    const {
        disableLargeFilesCheckbox,
        disableStart,
        isLargeFile,
        keypath,
        matchingIcon,
        mode,
        outpath,
        password,
        passwordRepeated,
        passwordType,
        requirePassword,
        requirePasswordRepeated,
        showMatchingIcon,
        showVisibilityIcon,
        statusErr,
        statusOk,
        visibilityIcon,
    } = state;


    return (
        <div className="container">
            <div className="row">
                <a href="https://github.com/alexylon/Ferrocrypt" target="_blank">
                    <img src="/padlock-red-256.png" className="logo ferrocrypt" alt="Ferrocrypt logo"/>
                </a>
            </div>
            <div>
                <div className={`helper ${mode !== "gk" ? '' : 'disabled'}`}>Drop a file or a folder into app's
                    window
                </div>
                <div className="row">
                    <input
                        id="inpath"
                        disabled={true}
                        value={mode === "gk" ? "" : state.inpath}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button onClick={handleClear} style={{width: "90px"}}>Clear</button>
                </div>
                <div className="cbx-form">
                    <label htmlFor="rdo1">
                        <input
                            type="radio"
                            id="rdo1"
                            name="radio"
                            onChange={handleSymmetricEncryptionMode}
                            checked={mode === "se" || mode === "sd"}
                        />
                        <span className="rdo"></span>
                        <span>Symmetric</span>
                    </label>
                    <span className="spacer-15"/>
                    <label htmlFor="rdo2">
                        <input
                            type="radio"
                            id="rdo2"
                            name="radio"
                            onChange={handleHybridEncryptionMode}
                            checked={mode === "he" || mode === "hd"}
                        />
                        <span className="rdo"></span>
                        <span>Hybrid</span>
                    </label>
                    <span className="spacer-15"/>
                    <label htmlFor="rdo3">
                        <input
                            type="radio"
                            id="rdo3"
                            name="radio"
                            onChange={handleGenerateKeyPairMode}
                            checked={mode === "gk"}
                        />
                        <span className="rdo"></span>
                        <span>Create key pair</span>
                    </label>
                </div>
                <label className={`helper ${requirePassword ? '' : 'disabled'}`}>Password:</label>
                <div className="row">
                    <input
                        id="password-input"
                        type={passwordType}
                        value={requirePassword ? password : ""}
                        disabled={!requirePassword}
                        onChange={(e) => handlePasswordChange(e.currentTarget.value)}
                        placeholder={requirePassword ? "Enter a password..." : ""}
                        style={{width: "100%"}}
                    />
                    <div className="visibility-icon">
                        {showVisibilityIcon &&
                            <img
                                src={visibilityIcon}
                                alt="visibility icon"
                                style={{width: "20px"}}
                                onClick={handlePasswordHide}
                            ></img>
                        }
                    </div>
                </div>
                <div className="row">
                    <input
                        id="repeat-password-input"
                        type="password"
                        value={requirePasswordRepeated ? passwordRepeated : ""}
                        disabled={!requirePasswordRepeated}
                        onChange={(e) => handleRepeatedPasswordChange(e.currentTarget.value)}
                        placeholder={requirePasswordRepeated ? "Repeat the password..." : ""}
                        style={{width: "100%"}}
                    />
                    <div className="match-icon">
                        {showMatchingIcon &&
                            <img
                                src={matchingIcon}
                                alt="match icon"
                                style={{width: "20px"}}
                            ></img>
                        }
                    </div>
                </div>
                <label className={`helper ${mode === "se" || mode === "sd" || mode === "gk" ? 'disabled' : ''}`}>Select
                    a key:</label>
                <div className="row">
                    <input
                        id="key"
                        disabled={true}
                        value={keypath}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button
                        onClick={handleSelectKey}
                        disabled={mode === "se" || mode === "sd" || mode === "gk"}
                        style={{width: "90px"}}
                    >Select
                    </button>
                </div>
                <div className="cbx-form">
                    <label htmlFor="checkbox1">
                        <input type="checkbox"
                               id="checkbox1"
                               checked={isLargeFile}
                               onChange={handleLargeFileSupport}
                               disabled={disableLargeFilesCheckbox}
                        />
                        <span className="cbx">
                            <svg width="12px" height="11px" viewBox="0 0 12 11">
                                <polyline points="1 6.29411765 4.5 10 11 1"/>
                            </svg>
                        </span>
                        <span className="cbx-label">Large files (low RAM usage)</span>
                    </label>
                </div>
                <div className="helper">Save output to this folder:</div>
                <div className="row">
                    <input
                        id="outpath"
                        disabled={true}
                        value={outpath}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button onClick={handleSelectOutputDir} style={{width: "90px"}}>Select</button>
                </div>
                <hr className="solid"/>
                <div className="row">
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            handleStart().then();
                        }}
                    >
                        <button
                            type="submit"
                            style={{width: "350px"}}
                            disabled={disableStart}
                        >Start
                        </button>
                    </form>
                </div>
                <div className="helper" style={{color: "darkseagreen"}}> {statusOk} </div>
                <div className="helper" style={{color: "#C41E3A"}}> {statusErr} </div>
            </div>
        </div>
    )
        ;
}

export default App;
