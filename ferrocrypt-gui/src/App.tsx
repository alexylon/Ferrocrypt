import {useEffect, useState} from "react";
import {invoke} from "@tauri-apps/api/tauri";
import "./App.css";
import {open} from "@tauri-apps/api/dialog";
import {listen} from '@tauri-apps/api/event'

const initialState = {
    inpath: "",
    outpath: "",
    password: "",
    passwordRepeated: "",
    requirePasswordRepeated: true,
    statusOk: "Ready",
    statusErr: "",
    isLargeFile: false,
    decryptionMode: false,
    checkboxDisabled: false,
    startDisabled: true,
    hidePassword: true,
    passwordType: "password",
    visibilityIcon: "/icon-unhide-50.png",
};

function App() {
    const [state, setState] = useState(initialState);

    listen('tauri://file-drop', (event: any) => {
        setState(prevState => ({
            ...prevState,
            inpath: event.payload[0]
        }));
    }).then();

    useEffect(() => {
        let lastIndex = state.inpath.lastIndexOf(".");
        let extension = state.inpath.substring(lastIndex);
        if (extension === ".fcv") {
            setState(prevState => ({
                ...prevState,
                decryptionMode: true
            }));
        } else {
            setState(prevState => ({
                ...prevState,
                decryptionMode: false
            }));
        }
    }, [state.inpath]);

    useEffect(() => {
        const {decryptionMode, hidePassword} = state;
        if (decryptionMode) {
            setState(prevState => ({
                ...prevState,
                checkboxDisabled: true,
                requirePasswordRepeated: false
            }));
            if (hidePassword) {
                setState(prevState => ({
                    ...prevState,
                    visibilityIcon: "/icon-unhide-50.png",
                    passwordType: "password"
                }));
            } else {
                setState(prevState => ({
                    ...prevState,
                    visibilityIcon: "/icon-hide-50.png",
                    passwordType: "text"
                }));
            }
        } else {
            setState(prevState => ({
                ...prevState,
                checkboxDisabled: false
            }));
            if (hidePassword) {
                setState(prevState => ({
                    ...prevState,
                    visibilityIcon: "/icon-unhide-50.png",
                    passwordType: "password",
                    requirePasswordRepeated: true
                }));
            } else {
                setState(prevState => ({
                    ...prevState,
                    visibilityIcon: "/icon-hide-50.png",
                    passwordType: "text",
                    requirePasswordRepeated: false
                }));
            }
        }

    }, [state.decryptionMode, state.hidePassword]);

    useEffect(() => {
        const {inpath, password, passwordRepeated, requirePasswordRepeated} = state;
        if ((password === passwordRepeated || !requirePasswordRepeated) && inpath !== "") {
            setState(prevState => ({
                ...prevState,
                startDisabled: false
            }));
        } else {
            setState(prevState => ({
                ...prevState,
                startDisabled: true
            }));
        }
    }, [state.inpath, state.password, state.passwordRepeated, state.requirePasswordRepeated]);

    const handleOutputDirSelect = async () => {
        const selected = await open({
            multiple: false,
            directory: true
        }) as string;

        setState(prevState => ({
            ...prevState,
            outpath: selected
        }));
    };

    const handlePasswordChange = (value: string) => {
        setState(prevState => ({
            ...prevState,
            password: value
        }));
    }

    const handleRepeatedPasswordChange = (value: string) => {
        setState(prevState => ({
            ...prevState,
            passwordRepeated: value
        }));
    }

    const handleLargeFileSupport = () => {
        setState(prevState => ({
            ...prevState,
            isLargeFile: !state.isLargeFile
        }));
    }

    const handlePasswordHide = () => {
        setState(prevState => ({
            ...prevState,
            hidePassword: !state.hidePassword
        }));
    }

    const handleStart = async () => {
        const {inpath, outpath, password, isLargeFile} = state;
        await invoke("start", {inpath, outpath, password, isLargeFile})
            .then((message: any) => {
                setState(prevState => ({
                    ...prevState,
                    statusOk: message,
                    statusErr: "",
                }));
            })
            .catch((error: string) => {
                setState(prevState => ({
                    ...prevState,
                    statusOk: "",
                    statusErr: error,
                }));
            });
    }

    const handleClear = () => setState(initialState);

    const {
        outpath,
        password,
        passwordRepeated,
        requirePasswordRepeated,
        statusOk,
        statusErr,
        isLargeFile,
        checkboxDisabled,
        startDisabled,
        passwordType,
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
                <div className="helper">Password:</div>
                <div className="row">
                    <input
                        id="password-input"
                        type={passwordType}
                        value={password}
                        onChange={(e) => handlePasswordChange(e.currentTarget.value)}
                        placeholder="Enter a password..."
                        style={{width: "100%"}}
                    />
                    <div className="visibility-icon">
                        <img
                            src={visibilityIcon}
                            alt="visibility icon"
                            style={{width: "20px"}}
                            onClick={handlePasswordHide}
                        ></img>
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
                </div>
                <div className="checkbox-wrapper parent">
                    <label>
                        <input
                            className="child"
                            type="checkbox"
                            checked={isLargeFile}
                            onChange={handleLargeFileSupport}
                            disabled={checkboxDisabled}
                        />
                        <span className="child">Large file(s) (low memory usage)</span>
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
                    <button onClick={handleOutputDirSelect} style={{width: "90px"}}>Select</button>
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
                            disabled={startDisabled}
                        >Start
                        </button>
                    </form>
                </div>
                <div className="helper" style={{color: "darkseagreen"}}> {statusOk} </div>
                <div className="helper" style={{color: "#C41E3A"}}> {statusErr} </div>
            </div>
        </div>
    );
}

export default App;
