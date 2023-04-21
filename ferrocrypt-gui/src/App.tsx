import {useEffect, useState} from "react";
import {invoke} from "@tauri-apps/api/tauri";
import "./App.css";
import {open} from "@tauri-apps/api/dialog";
import {listen} from '@tauri-apps/api/event'

function App() {
    const [inpath, setInpath] = useState("");
    const [outpath, setOutpath] = useState("");
    const [password, setPassword] = useState("");
    const [passwordRepeated, setPasswordRepeated] = useState("");
    const [requirePasswordRepeated, setRequirePasswordRepeated] = useState(true);
    const [statusOk, setStatusOk] = useState("Ready");
    const [statusErr, setStatusErr] = useState("");
    const [isLargeFile, setIsLargeFile] = useState(false);
    const [decryptionMode, setDecryptionMode] = useState(false);
    const [checkboxDisabled, setCheckboxDisabled] = useState(false);
    const [startDisabled, setStartDisabled] = useState(true);
    const [hidePassword, setHidePassword] = useState(true);
    const [passwordType, setPasswordType] = useState("password");
    const [visibilityIcon, setVisibilityIcon] = useState("/icon-unhide-50.png");

    // let counter = 1;
    listen('tauri://file-drop', (event: any) => {
        // console.log("counter: ", counter);
        console.log("event: ", event)
        // counter += 1;
        setInpath(event.payload[0]);
    }).then();

    useEffect(() => {
        let lastIndex = inpath.lastIndexOf(".");
        let extension = inpath.substring(lastIndex);
        if (extension === ".fcv") {
            setDecryptionMode(true);
        } else {
            setDecryptionMode(false);
        }
    }, [inpath]);

    useEffect(() => {
        if (decryptionMode) {
            setCheckboxDisabled(true);
            setRequirePasswordRepeated(false);
            if (hidePassword) {
                setVisibilityIcon("/icon-unhide-50.png");
                setPasswordType("password");
            } else {
                setVisibilityIcon("/icon-hide-50.png");
                setPasswordType("text");
            }
        } else {
            setCheckboxDisabled(false);
            // setRequirePasswordRepeated(true);
            if (hidePassword) {
                setVisibilityIcon("/icon-unhide-50.png");
                setPasswordType("password");
                setRequirePasswordRepeated(true);
            } else {
                setVisibilityIcon("/icon-hide-50.png");
                setPasswordType("text");
                setRequirePasswordRepeated(false);
            }
        }

    }, [decryptionMode, hidePassword]);

    useEffect(() => {
        if ((password === passwordRepeated || !requirePasswordRepeated) && inpath !== "") {
            setStartDisabled(false);
        } else {
            setStartDisabled(true);
        }
    }, [inpath, password, passwordRepeated, requirePasswordRepeated]);

    const selectDir = async () => {
        const selected = await open({
            multiple: false,
            directory: true
        }) as string;

        setOutpath(selected);

        console.log("selected: ", selected);
    };

    const clear = async () => {
        setInpath("");
        setOutpath("");
        setPassword("");
        setPasswordRepeated("");
        setRequirePasswordRepeated(true);
        setStatusOk("Ready");
        setStatusErr("");
        setIsLargeFile(false);
        setDecryptionMode(false);
        setCheckboxDisabled(false);
        setStartDisabled(true);
        setHidePassword(true);
        setPasswordType("password");
        setVisibilityIcon("/icon-unhide-50.png");
    };

    const start = async () => {
        await invoke("start", {inpath, outpath, password, isLargeFile})
            .then((message: any) => {
                setStatusErr("");
                setStatusOk(message);
                console.log("message: ", message);
            })
            .catch((error: string) => {
                setStatusOk("");
                setStatusErr(error);
            });
    }

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
                        value={inpath}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button onClick={clear} style={{width: "90px"}}>Clear</button>
                </div>
                <div className="helper">Password:</div>
                <div className="row">
                    <input
                        id="password-input"
                        type={passwordType}
                        value={password}
                        onChange={(e) => setPassword(e.currentTarget.value)}
                        placeholder="Enter a password..."
                        style={{width: "100%"}}
                    />
                    <div className="visibility-icon">
                        <img
                            src={visibilityIcon}
                            alt="visibility icon"
                            style={{width: "20px"}}
                            onClick={() => setHidePassword((prev) => !prev)}
                        ></img>
                    </div>
                </div>
                <div className="row">
                    <input
                        id="repeat-password-input"
                        type="password"
                        value={requirePasswordRepeated ? passwordRepeated : ""}
                        disabled={!requirePasswordRepeated}
                        onChange={(e) => setPasswordRepeated(e.currentTarget.value)}
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
                            onChange={() => setIsLargeFile((prev) => !prev)}
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
                    <button onClick={selectDir} style={{width: "90px"}}>Select</button>
                </div>
                <hr className="solid"/>
                <div className="row">
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            start().then();
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
