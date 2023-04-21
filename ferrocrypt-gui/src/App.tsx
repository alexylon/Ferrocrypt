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
    const [allowed, setAllowed] = useState(false);
    const [disabled, setDisabled] = useState(false);
    const [startDisabled, setStartDisabled] = useState(false);

    listen('tauri://file-drop', (event: any) => {
        console.log(event)
        setInpath(event.payload[0]);
    }).then();

    useEffect(() => {
        let lastIndex = inpath.lastIndexOf(".");
        let extension = inpath.substring(lastIndex);
        if (extension === ".fcv") {
            setDisabled(true);
            setRequirePasswordRepeated(false);
        } else {
            setDisabled(false);
            setRequirePasswordRepeated(true);
        }
    }, [inpath]);

    useEffect(() => {
        if ((password === passwordRepeated || !requirePasswordRepeated) && inpath !== "") {
            setAllowed(true);
            setStartDisabled(false);
        } else {
            setAllowed(false);
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
        setStatusErr("");
        setInpath("");
        setPassword("");
        setPasswordRepeated("");
        setOutpath("");
        setIsLargeFile(false);
        setStatusOk("Ready");
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
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.currentTarget.value)}
                        placeholder="Enter a password..."
                        style={{width: "100%"}}
                    />
                </div>
                <div className="row">
                    <input
                        id="repeat-password-input"
                        type="password"
                        value={passwordRepeated}
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
                            disabled={disabled}
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
