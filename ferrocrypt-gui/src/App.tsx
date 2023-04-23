import {useEffect, useState} from "react";
import {invoke} from "@tauri-apps/api/tauri";
import {listen} from '@tauri-apps/api/event'
import {open} from "@tauri-apps/api/dialog";
import "./App.css";

interface AppState {
    decryptionMode: boolean;
    disableCheckbox: boolean;
    disableStart: boolean;
    hidePassword: boolean;
    inpath: string;
    isLargeFile: boolean;
    matchingIcon: string;
    outpath: string;
    password: string;
    passwordMatch: boolean;
    passwordRepeated: string;
    passwordType: string;
    requirePasswordRepeated: boolean;
    showMatchingIcon: boolean;
    statusErr: string;
    statusOk: string;
    visibilityIcon: string;
}

const initialState: AppState = {
    decryptionMode: false,
    disableCheckbox: false,
    disableStart: true,
    hidePassword: true,
    inpath: "",
    isLargeFile: false,
    matchingIcon: "/icon-dot-red-30.png",
    outpath: "",
    password: "",
    passwordMatch: false,
    passwordRepeated: "",
    passwordType: "password",
    requirePasswordRepeated: true,
    showMatchingIcon: false,
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
        const {hidePassword, inpath, password, passwordRepeated, requirePasswordRepeated} = state;

        const fileExtension = inpath.slice(inpath.lastIndexOf("."));
        const decryptionMode = fileExtension === ".fcv";

        if (decryptionMode) {
            updateState({
                disableStart: inpath === "" || password.length < 1,
                disableCheckbox: true,
                requirePasswordRepeated: false,
                visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png",
                passwordType: hidePassword ? "password" : "text",
                showMatchingIcon: false,
            });
        } else {
            updateState({
                disableStart: inpath === "" || password.length < 1 || (password !== passwordRepeated && requirePasswordRepeated),
                disableCheckbox: false,
                requirePasswordRepeated: hidePassword,
                visibilityIcon: hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png",
                passwordType: hidePassword ? "password" : "text",
                showMatchingIcon: hidePassword ? !!passwordRepeated : false,
                matchingIcon: hidePassword && !!passwordRepeated && password === passwordRepeated
                    ? "/icon-dot-green-30.png"
                    : "/icon-dot-red-30.png",
            });
        }
    }, [state.decryptionMode, state.hidePassword, state.inpath, state.password, state.passwordRepeated, state.requirePasswordRepeated]);

    const handleOutputDirSelect = async () => {
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

    const handlePasswordHide = () => {
        updateState({
            hidePassword: !state.hidePassword
        });
    }

    const handleStart = async () => {
        const {inpath, outpath, password, isLargeFile} = state;
        await invoke("start", {inpath, outpath, password, isLargeFile})
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
        outpath,
        password,
        passwordRepeated,
        requirePasswordRepeated,
        statusOk,
        statusErr,
        isLargeFile,
        disableCheckbox,
        disableStart,
        passwordType,
        visibilityIcon,
        matchingIcon,
        showMatchingIcon,
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
                <div className="checkbox-wrapper parent">
                    <label>
                        <input
                            className="child"
                            type="checkbox"
                            checked={isLargeFile}
                            onChange={handleLargeFileSupport}
                            disabled={disableCheckbox}
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
                            disabled={disableStart}
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
