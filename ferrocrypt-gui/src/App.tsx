import {useEffect, useState} from "react";
import {invoke} from "@tauri-apps/api/tauri";
import {listen} from '@tauri-apps/api/event'
import {open} from "@tauri-apps/api/dialog";
import "./App.css";

interface AppState {
    symmetricDecryptionMode: boolean;
    disableLargeFilesCheckbox: boolean;
    disableStart: boolean;
    hidePassword: boolean;
    inpath: string;
    isLargeFile: boolean;
    keypath: string;
    matchingIcon: string;
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
    symmetricEncryptionMode: boolean;
    visibilityIcon: string;
}

const initialState: AppState = {
    symmetricDecryptionMode: false,
    disableLargeFilesCheckbox: false,
    disableStart: true,
    hidePassword: true,
    inpath: "",
    isLargeFile: false,
    keypath: "",
    matchingIcon: "/icon-dot-red-30.png",
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
    symmetricEncryptionMode: true,
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

        const fileExtension = inpath.slice(inpath.lastIndexOf("."));
        const symmetricDecryptionMode = fileExtension === ".fcs";
        const hybridDecryptionMode = fileExtension === ".fch";

        if (symmetricDecryptionMode) {
            updateState({
                disableStart: inpath === "" || password.length < 1,
                disableLargeFilesCheckbox: true,
                requirePasswordRepeated: false,
                visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png",
                passwordType: hidePassword ? "password" : "text",
                showMatchingIcon: false,
                showVisibilityIcon: true,
            });
        } else if (hybridDecryptionMode) {
            updateState({
                disableStart: inpath === "" || password.length < 1 || keypath === "",
                disableLargeFilesCheckbox: true,
                requirePasswordRepeated: false,
                visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png",
                passwordType: hidePassword ? "password" : "text",
                showMatchingIcon: false,
                showVisibilityIcon: true,
                symmetricEncryptionMode: false
            });
        } else if (!hybridDecryptionMode && !symmetricEncryptionMode && !symmetricDecryptionMode) { // Hybrid encryption mode
            updateState({
                disableStart: inpath === "" || keypath === "",
                disableLargeFilesCheckbox: false,
                requirePassword: false,
                requirePasswordRepeated: false,
                passwordType: hidePassword ? "password" : "text",
                showMatchingIcon: false,
                showVisibilityIcon: false,
                symmetricEncryptionMode: false
            });
        } else { // Symmetric encryption mode
            updateState({
                disableStart: inpath === "" || password.length < 1 || (password !== passwordRepeated && requirePasswordRepeated),
                disableLargeFilesCheckbox: false,
                requirePassword: true,
                requirePasswordRepeated: hidePassword,
                visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png",
                passwordType: hidePassword ? "password" : "text",
                showMatchingIcon: hidePassword ? !!passwordRepeated : false,
                showVisibilityIcon: true,
                matchingIcon: hidePassword && !!passwordRepeated && password === passwordRepeated
                    ? "/icon-dot-green-30.png"
                    : "/icon-dot-red-30.png",
            });
        }
    }, [
        state.symmetricEncryptionMode,
        state.symmetricDecryptionMode,
        state.hidePassword,
        state.inpath,
        state.keypath,
        state.password,
        state.passwordRepeated,
        state.requirePassword,
        state.requirePasswordRepeated
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

    const handleEncryptionMode = () => {
        updateState({
            symmetricEncryptionMode: !symmetricEncryptionMode
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

        const {inpath, outpath, password, isLargeFile, keypath, symmetricEncryptionMode} = state;
        await invoke("start", {inpath, outpath, password, isLargeFile, keypath, symmetricEncryptionMode})
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
                    statusErr: error,
                });
            });
    }

    const handleClear = () => setState(initialState);

    const {
        keypath,
        outpath,
        password,
        passwordRepeated,
        requirePasswordRepeated,
        requirePassword,
        statusOk,
        statusErr,
        isLargeFile,
        disableLargeFilesCheckbox,
        disableStart,
        passwordType,
        visibilityIcon,
        matchingIcon,
        symmetricEncryptionMode,
        showMatchingIcon,
        showVisibilityIcon,
    } = state;


    return (
        <div className="container">
            <div className="row">
                <a href="https://github.com/alexylon/Ferrocrypt" target="_blank">
                    <img src="/padlock-red-256.png" className="logo ferrocrypt" alt="Ferrocrypt logo"/>
                </a>
            </div>
            <div>
                <div className="helper">Drop a file or a folder into app's window</div>
                <div className="row">
                    <input
                        id="inpath"
                        disabled={true}
                        value={state.inpath}
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
                            onChange={handleEncryptionMode}
                            checked={symmetricEncryptionMode}
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
                            onChange={handleEncryptionMode}
                            checked={!symmetricEncryptionMode}
                        />
                        <span className="rdo"></span>
                        <span>Hybrid</span>
                    </label>
                </div>
                <label className={`helper ${requirePassword ? '' : 'disabled'}`}>Password:</label>
                <div className="row">
                    <input
                        id="password-input"
                        type={passwordType}
                        value={password}
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
                <label className={`helper ${!symmetricEncryptionMode ? '' : 'disabled'}`}>Select a key:</label>
                <div className="row">
                    <input
                        id="outpath"
                        disabled={true}
                        value={keypath}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button
                        onClick={handleSelectKey}
                        disabled={symmetricEncryptionMode}
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
