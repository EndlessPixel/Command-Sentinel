// 全局存储规则配置
let riskRules = null;

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', async function () {
    // 1. 加载风险规则配置
    try {
        const response = await fetch('rules.json');
        if (!response.ok) throw new Error('规则文件加载失败');
        riskRules = await response.json();
        console.log('风险规则加载成功');
    } catch (e) {
        alert(`规则加载失败：${e.message}，请检查rules.json文件是否存在`);
        return;
    }

    // 2. 标签切换逻辑
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function () {
            tabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            this.classList.add('active');
            const tabId = this.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // 3. 绑定检测按钮事件
    document.getElementById('windows-check').addEventListener('click', function () {
        const command = document.getElementById('windows-command').value.trim();
        const result = detectRisk(command, 'windows');
        showResult('windows-result', result);
    });

    document.getElementById('linux-check').addEventListener('click', function () {
        const command = document.getElementById('linux-command').value.trim();
        const result = detectRisk(command, 'linux');
        showResult('linux-result', result);
    });
});

/**
 * Base64解码函数（处理常见的Base64编码命令）
 * @param {string} str - 待解码的字符串
 * @returns {string} 解码后的字符串（解码失败返回原字符串）
 */
function base64Decode(str) {
    try {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        while (str.length % 4) str += '=';
        return atob(str);
    } catch (e) {
        return str;
    }
}

/**
 * 提取命令中的Base64编码内容并解码
 * @param {string} command - 原始命令
 * @returns {object} { hasBase64: 是否包含Base64, decodeStr: 解码后的内容 }
 */
function extractAndDecodeBase64(command) {
    if (!riskRules?.common?.base64) return { hasBase64: false, decodeStr: '' };

    const base64Regex = new RegExp(riskRules.common.base64.regex, 'gi');
    let hasBase64 = false;
    let decodeStr = '';
    let match;

    while ((match = base64Regex.exec(command)) !== null) {
        hasBase64 = true;
        const base64Str = match[1] || match[0];
        const decoded = base64Decode(base64Str);
        decodeStr += `Base64解码内容：${decoded}\n`;
    }

    return { hasBase64, decodeStr };
}

/**
 * 核心风险检测函数（根据规则配置检测）
 * @param {string} command - 待检测命令
 * @param {string} osType - 系统类型（windows/linux）
 * @returns {object} 检测结果
 */
function detectRisk(command, osType) {
    // 空命令处理
    if (!command) {
        return { level: 'safe', message: '未输入任何命令' };
    }

    // 初始化结果
    let result = {
        level: 'safe',
        message: '命令未检测到风险',
        decodeInfo: ''
    };

    // 1. 检测通用规则（Base64/远程URL/function等）
    const commonRules = riskRules.common;
    for (const [ruleKey, rule] of Object.entries(commonRules)) {
        const regex = new RegExp(rule.regex, 'gi');
        if (regex.test(command)) {
            // Base64需要额外解码检测
            if (ruleKey === 'base64') {
                const base64Result = extractAndDecodeBase64(command);
                result.decodeInfo = base64Result.decodeStr;

                // 解码后的内容再次检测
                if (base64Result.decodeStr) {
                    const decodeCommand = base64Result.decodeStr.replace('Base64解码内容：', '');
                    const decodeResult = detectRisk(decodeCommand, osType);
                    if (decodeResult.level !== 'safe') {
                        result.level = decodeResult.level;
                        result.message = `Base64解码后：${decodeResult.message}`;
                        return result;
                    }
                }
            }

            // 通用规则仅在当前无更高风险时生效
            if (result.level === 'safe') {
                result.level = rule.level;
                result.message = rule.message;
            }
        }
    }

    // 2. 检测系统专属规则（优先级：极其危险 > 危险 > 风险）
    const osRules = riskRules[osType];
    // 先检测极其危险规则
    if (osRules.extreme_danger) {
        for (const rule of osRules.extreme_danger) {
            const regex = new RegExp(rule.regex, 'gi');
            if (regex.test(command)) {
                result.level = 'extreme-danger';
                result.message = rule.message;
                return result; // 极其危险直接返回，无需检测其他规则
            }
        }
    }

    // 再检测危险规则
    if (osRules.danger && result.level !== 'extreme-danger') {
        for (const rule of osRules.danger) {
            const regex = new RegExp(rule.regex, 'gi');
            if (regex.test(command)) {
                result.level = 'danger';
                result.message = rule.message;
                return result; // 危险直接返回
            }
        }
    }

    // 最后检测系统专属风险规则
    if (osRules.risk && result.level === 'safe') {
        for (const rule of osRules.risk) {
            const regex = new RegExp(rule.regex, 'gi');
            if (regex.test(command)) {
                result.level = 'risk';
                result.message = rule.message;
                return result;
            }
        }
    }

    // 拼接Base64解码信息
    if (result.decodeInfo) {
        result.message = `${result.message}\n\n${result.decodeInfo}`;
    }

    return result;
}

/**
 * 展示检测结果
 * @param {string} resultId - 结果容器ID
 * @param {object} result - 检测结果
 */
function showResult(resultId, result) {
    const resultContent = document.querySelector(`#${resultId} .result-content`);
    resultContent.className = 'result-content';
    resultContent.classList.add(result.level);
    resultContent.innerHTML = result.message.replace(/\n/g, '<br>');
}