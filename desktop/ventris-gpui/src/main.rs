use std::env;
use std::path::PathBuf;

use gpui::{
    div, prelude::*, px, rgb, size, App, Application, Bounds, Context, KeyDownEvent, Window,
    WindowBounds, WindowOptions,
};
use gpui_component::{
    button::{Button, ButtonVariants},
    Selectable,
};
use ventris_db::{
    Project, ProjectAssertion, ProjectData, ProjectFunction, ProjectReference,
    ProjectReferenceKind, ProjectSegment, ProjectSymbol,
};

// The palette deliberately follows the low-contrast, high-density convention used by mature
// reverse-engineering tools: one background, one raised surface, one selection color, and a small
// number of semantic accents. Keeping this local also makes a future theme editor straightforward.
const BG: u32 = 0x0d1016;
const SIDEBAR: u32 = 0x141820;
const SURFACE: u32 = 0x181d26;
const RAISED: u32 = 0x202631;
const CARD: u32 = 0x252c38;
const HOVER: u32 = 0x2b3544;
const SELECTED: u32 = 0x294466;
const BORDER: u32 = 0x303a49;
const TEXT: u32 = 0xe7ebf2;
const MUTED: u32 = 0x8d98a9;
const SUBTLE: u32 = 0x667184;
const ACCENT: u32 = 0x7db7ff;
const GREEN: u32 = 0x57d39b;
const AMBER: u32 = 0xe7b86d;
const RED: u32 = 0xef8585;
const PURPLE: u32 = 0xc9a6ff;
const CODE_BG: u32 = 0x11161e;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FunctionRow {
    address: u64,
    name: String,
    size: u64,
    signature: Option<String>,
    comment: Option<String>,
    provenance: Option<String>,
    confidence: u8,
    generation: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DataRow {
    address: u64,
    name: String,
    size: u64,
    type_name: String,
    comment: Option<String>,
    provenance: Option<String>,
    confidence: u8,
    generation: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReferenceRow {
    id: usize,
    from: u64,
    to: u64,
    kind: String,
    offset: Option<i64>,
    confidence: u8,
    generation: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SegmentRow {
    name: String,
    address: u64,
    size: u64,
    file_offset: u64,
    file_size: u64,
    permissions: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolRow {
    address: u64,
    name: String,
    size: u64,
    section: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AssertionRow {
    address: u64,
    kind: String,
    value: String,
    note: String,
    authority: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum WorkspaceView {
    Functions,
    Data,
    References,
    Segments,
    Symbols,
    Assertions,
}

impl WorkspaceView {
    fn label(self) -> &'static str {
        match self {
            Self::Functions => "Functions",
            Self::Data => "Data",
            Self::References => "References",
            Self::Segments => "Segments",
            Self::Symbols => "Symbols",
            Self::Assertions => "Assertions",
        }
    }

    fn short_label(self) -> &'static str {
        match self {
            Self::Functions => "Functions",
            Self::Data => "Data",
            Self::References => "Xrefs",
            Self::Segments => "Memory",
            Self::Symbols => "Symbols",
            Self::Assertions => "Facts",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DetailTab {
    Decompile,
    Assembly,
    Graph,
    Facts,
    Xrefs,
}

impl DetailTab {
    fn label(self) -> &'static str {
        match self {
            Self::Decompile => "Pseudocode",
            Self::Assembly => "Assembly",
            Self::Graph => "Flow",
            Self::Facts => "Facts",
            Self::Xrefs => "Xrefs",
        }
    }
}

#[derive(Debug)]
struct ProjectWorkspace {
    project_path: PathBuf,
    source: String,
    loader: String,
    target: String,
    image_hash: u64,
    base: Option<u64>,
    entry: Option<u64>,
    file_size: u64,
    functions: Vec<FunctionRow>,
    data: Vec<DataRow>,
    references: Vec<ReferenceRow>,
    segments: Vec<SegmentRow>,
    symbols: Vec<SymbolRow>,
    assertions: Vec<AssertionRow>,
    active_view: WorkspaceView,
    detail_tab: DetailTab,
    selected_address: Option<u64>,
    selected_data: Option<u64>,
    selected_reference: Option<usize>,
    query: String,
    search_focused: bool,
    status: String,
}

impl ProjectWorkspace {
    fn from_project(project_path: PathBuf, project: Project) -> Self {
        let selected_address = project.functions.first().map(|function| function.address);
        let functions = project
            .functions
            .iter()
            .map(FunctionRow::from_project)
            .collect();
        let data = project.data.iter().map(DataRow::from_project).collect();
        let references = project
            .references
            .iter()
            .enumerate()
            .map(|(id, reference)| ReferenceRow::from_project(id, reference))
            .collect();
        let segments = project
            .image
            .segments
            .iter()
            .map(SegmentRow::from_project)
            .collect();
        let symbols = project
            .image
            .symbols
            .iter()
            .map(SymbolRow::from_project)
            .collect();
        let assertions = project
            .assertions
            .iter()
            .map(AssertionRow::from_project)
            .collect();
        Self {
            project_path,
            source: project.image.source,
            loader: project.image.loader,
            target: project.image.target.unwrap_or_else(|| "unassigned".into()),
            image_hash: project.image.content_hash,
            base: project.image.base,
            entry: project.image.entry,
            file_size: project.image.file_size,
            functions,
            data,
            references,
            segments,
            symbols,
            assertions,
            active_view: WorkspaceView::Functions,
            detail_tab: DetailTab::Decompile,
            selected_address,
            selected_data: None,
            selected_reference: None,
            query: String::new(),
            search_focused: false,
            status: "Project facts loaded".into(),
        }
    }

    fn selected_function(&self) -> Option<&FunctionRow> {
        self.selected_address.and_then(|address| {
            self.functions
                .iter()
                .find(|function| function.address == address)
        })
    }

    fn selected_data_row(&self) -> Option<&DataRow> {
        self.selected_data
            .and_then(|address| self.data.iter().find(|data| data.address == address))
    }

    fn selected_reference_row(&self) -> Option<&ReferenceRow> {
        self.selected_reference
            .and_then(|id| self.references.iter().find(|reference| reference.id == id))
    }

    fn query_matches(&self, text: &str) -> bool {
        self.query.is_empty()
            || text
                .to_ascii_lowercase()
                .contains(&self.query.to_ascii_lowercase())
    }

    fn function_matches(&self, function: &FunctionRow) -> bool {
        self.query_matches(&format!(
            "{} {} 0x{:x} {}",
            function.name,
            function.signature.as_deref().unwrap_or(""),
            function.address,
            function.comment.as_deref().unwrap_or("")
        ))
    }

    fn data_matches(&self, data: &DataRow) -> bool {
        self.query_matches(&format!(
            "{} {} {} 0x{:x} {}",
            data.name,
            data.type_name,
            data.address,
            data.size,
            data.comment.as_deref().unwrap_or("")
        ))
    }

    fn reference_matches(&self, reference: &ReferenceRow) -> bool {
        self.query_matches(&format!(
            "{} 0x{:x} 0x{:x}",
            reference.kind, reference.from, reference.to
        ))
    }

    fn count_for(&self, view: WorkspaceView) -> usize {
        match view {
            WorkspaceView::Functions => self
                .functions
                .iter()
                .filter(|item| self.function_matches(item))
                .count(),
            WorkspaceView::Data => self
                .data
                .iter()
                .filter(|item| self.data_matches(item))
                .count(),
            WorkspaceView::References => self
                .references
                .iter()
                .filter(|item| self.reference_matches(item))
                .count(),
            WorkspaceView::Segments => self.segments.len(),
            WorkspaceView::Symbols => self.symbols.len(),
            WorkspaceView::Assertions => self.assertions.len(),
        }
    }

    fn nav_button(&self, view: WorkspaceView, cx: &mut Context<Self>) -> impl IntoElement {
        let active = self.active_view == view;
        let count = self.count_for(view);
        Button::new(("nav", view as u64))
            .ghost()
            .selected(active)
            .compact()
            .w_full()
            .h(px(34.0))
            .px_3()
            .gap_2()
            .on_click(cx.listener(move |workspace, _, _, cx| {
                workspace.active_view = view;
                workspace.detail_tab = DetailTab::Decompile;
                workspace.search_focused = false;
                match view {
                    WorkspaceView::Functions => {
                        workspace.selected_data = None;
                        workspace.selected_reference = None;
                        if workspace.selected_address.is_none()
                            || workspace.selected_address.is_some_and(|address| {
                                !workspace.functions.iter().any(|f| f.address == address)
                            })
                        {
                            workspace.selected_address =
                                workspace.functions.first().map(|f| f.address);
                        }
                    }
                    WorkspaceView::Data => {
                        workspace.selected_data = workspace.data.first().map(|item| item.address);
                        workspace.selected_reference = None;
                    }
                    WorkspaceView::References => {
                        workspace.selected_reference =
                            workspace.references.first().map(|item| item.id);
                    }
                    WorkspaceView::Segments
                    | WorkspaceView::Symbols
                    | WorkspaceView::Assertions => {
                        workspace.selected_address = None;
                        workspace.selected_data = None;
                        workspace.selected_reference = None;
                    }
                }
                cx.notify();
            }))
            .child(
                div()
                    .w(px(18.0))
                    .text_center()
                    .text_color(rgb(if active { ACCENT } else { SUBTLE }))
                    .child(match view {
                        WorkspaceView::Functions => "ƒ",
                        WorkspaceView::Data => "◇",
                        WorkspaceView::References => "↗",
                        WorkspaceView::Segments => "▤",
                        WorkspaceView::Symbols => "S",
                        WorkspaceView::Assertions => "✓",
                    }),
            )
            .child(div().flex_1().child(view.short_label()))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(if active { TEXT } else { SUBTLE }))
                    .child(count.to_string()),
            )
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .w(px(238.0))
            .h_full()
            .flex()
            .flex_col()
            .gap_1()
            .p_3()
            .bg(rgb(SIDEBAR))
            .text_color(rgb(TEXT))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py_2()
                    .child(
                        div()
                            .w(px(24.0))
                            .h(px(24.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_sm()
                            .bg(rgb(ACCENT))
                            .text_color(rgb(BG))
                            .font_weight(gpui::FontWeight::BOLD)
                            .child("V"),
                    )
                    .child(
                        div()
                            .text_lg()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child("Ventris"),
                    ),
            )
            .child(
                div()
                    .px_2()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child("BINARY ANALYSIS WORKSPACE"),
            )
            .child(
                div()
                    .mt_4()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(SURFACE))
                    .child(div().text_xs().text_color(rgb(SUBTLE)).child("OPEN IMAGE"))
                    .child(div().mt_1().text_sm().truncate().child(self.source.clone()))
                    .child(
                        div()
                            .mt_1()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(format!("{} · {}", self.loader, self.target)),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_xs()
                            .font_family("Cascadia Code")
                            .text_color(rgb(SUBTLE))
                            .child(format!("hash {:016x}", self.image_hash)),
                    ),
            )
            .child(
                div()
                    .mt_4()
                    .px_2()
                    .text_xs()
                    .text_color(rgb(SUBTLE))
                    .child("ANALYSIS"),
            )
            .child(self.nav_button(WorkspaceView::Functions, cx))
            .child(self.nav_button(WorkspaceView::Data, cx))
            .child(self.nav_button(WorkspaceView::References, cx))
            .child(
                div()
                    .mt_3()
                    .px_2()
                    .text_xs()
                    .text_color(rgb(SUBTLE))
                    .child("IMAGE MODEL"),
            )
            .child(self.nav_button(WorkspaceView::Segments, cx))
            .child(self.nav_button(WorkspaceView::Symbols, cx))
            .child(self.nav_button(WorkspaceView::Assertions, cx))
            .child(div().flex_1())
            .child(
                div()
                    .p_3()
                    .rounded_md()
                    .bg(rgb(SURFACE))
                    .border_1()
                    .border_color(rgb(BORDER))
                    .child(div().text_xs().text_color(rgb(SUBTLE)).child("SESSION"))
                    .child(div().mt_1().text_sm().child(self.status.clone()))
                    .child(
                        div()
                            .mt_2()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child("Facts are persisted; edits remain evidence-backed."),
                    ),
            )
            .child(
                div()
                    .px_2()
                    .pt_2()
                    .text_xs()
                    .text_color(rgb(SUBTLE))
                    .child("/ search  ·  ↑↓ navigate  ·  Enter open  ·  Esc clear"),
            )
    }

    fn top_bar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let search_label = if self.query.is_empty() {
            "Search functions, symbols, xrefs…".to_string()
        } else {
            self.query.clone()
        };
        div()
            .h(px(58.0))
            .w_full()
            .flex()
            .items_center()
            .gap_3()
            .px_4()
            .bg(rgb(SURFACE))
            .border_color(rgb(BORDER))
            .border_1()
            .text_color(rgb(TEXT))
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child(format!("{} / {}", self.loader, self.target)),
            )
            .child(div().text_color(rgb(SUBTLE)).child("›"))
            .child(div().text_sm().truncate().child(self.source.clone()))
            .child(div().flex_1())
            .child(
                div()
                    .w(px(350.0))
                    .h(px(32.0))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .rounded_sm()
                    .border_1()
                    .border_color(rgb(if self.search_focused { ACCENT } else { BORDER }))
                    .bg(rgb(BG))
                    .id("search")
                    .on_click(cx.listener(|workspace, _, _, cx| {
                        workspace.search_focused = true;
                        cx.notify();
                    }))
                    .child(
                        div()
                            .text_color(rgb(if self.query.is_empty() { SUBTLE } else { TEXT }))
                            .truncate()
                            .child(search_label),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .px_1()
                            .rounded_sm()
                            .bg(rgb(RAISED))
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child("/"),
                    ),
            )
            .child(
                div()
                    .h(px(26.0))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .rounded_sm()
                    .bg(rgb(RAISED))
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(div().w(px(7.0)).h(px(7.0)).rounded_sm().bg(rgb(GREEN)))
                    .child("LOCAL MODEL"),
            )
    }

    fn section_header(&self, title: &str, count: usize) -> impl IntoElement {
        div()
            .flex()
            .items_center()
            .justify_between()
            .mb_2()
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::BOLD)
                    .child(title.to_string()),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(format!("{} shown", count)),
            )
    }

    fn list_shell(&self, title: &str, count: usize) -> gpui::Stateful<gpui::Div> {
        div()
            .w(px(360.0))
            .h_full()
            .flex()
            .flex_col()
            .p_3()
            .gap_2()
            .id(("list", count as u64))
            .overflow_y_scroll()
            .bg(rgb(BG))
            .border_color(rgb(BORDER))
            .border_1()
            .text_color(rgb(TEXT))
            .child(self.section_header(title, count))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(SUBTLE))
                    .child(if self.query.is_empty() {
                        "Sorted by address".to_string()
                    } else {
                        format!("Filtered by ‘{}’", self.query)
                    }),
            )
    }

    fn function_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let visible: Vec<_> = self
            .functions
            .iter()
            .filter(|function| self.function_matches(function))
            .collect();
        let mut list = self.list_shell("Functions", visible.len());
        if visible.is_empty() {
            return list.child(self.empty_state(
                "No matching functions",
                if self.query.is_empty() {
                    "The loader did not discover any function entries."
                } else {
                    "Try a name, address, signature, or comment."
                },
            ));
        }
        for function in visible {
            let address = function.address;
            let selected = self.selected_address == Some(address);
            let confidence_color = confidence_color(function.confidence);
            let mut row = div()
                .w_full()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(rgb(if selected { ACCENT } else { BORDER }))
                .bg(rgb(if selected { SELECTED } else { CARD }))
                .cursor_pointer()
                .hover(|style| style.bg(rgb(if selected { SELECTED } else { HOVER })))
                .id(("function", address))
                .on_click(cx.listener(move |workspace, _, _, cx| {
                    workspace.active_view = WorkspaceView::Functions;
                    workspace.selected_address = Some(address);
                    workspace.selected_data = None;
                    workspace.selected_reference = None;
                    workspace.detail_tab = DetailTab::Decompile;
                    workspace.status = format!("Selected 0x{address:x}");
                    cx.notify();
                }))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .w(px(7.0))
                                .h(px(7.0))
                                .rounded_sm()
                                .bg(rgb(confidence_color)),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(if selected { TEXT } else { ACCENT }))
                                .truncate()
                                .child(function.name.clone()),
                        )
                        .child(div().flex_1())
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(MUTED))
                                .font_family("Cascadia Code")
                                .child(format!("0x{:x}", address)),
                        ),
                )
                .child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(rgb(MUTED))
                        .truncate()
                        .child(
                            function
                                .signature
                                .clone()
                                .unwrap_or_else(|| "signature unavailable".into()),
                        ),
                )
                .child(
                    div()
                        .mt_2()
                        .flex()
                        .items_center()
                        .gap_2()
                        .text_xs()
                        .text_color(rgb(SUBTLE))
                        .child(format!("{} bytes", function.size))
                        .child("·")
                        .child(format!("{}% confidence", function.confidence))
                        .child(div().flex_1())
                        .child(format!("gen {}", function.generation)),
                );
            if let Some(comment) = &function.comment {
                row = row.child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(rgb(MUTED))
                        .line_clamp(2)
                        .child(comment.clone()),
                );
            }
            list = list.child(row);
        }
        list
    }

    fn data_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let visible: Vec<_> = self
            .data
            .iter()
            .filter(|item| self.data_matches(item))
            .collect();
        let mut list = self.list_shell("Data", visible.len());
        if visible.is_empty() {
            return list.child(self.empty_state(
                "No matching data",
                "Recovered globals and fields will appear here.",
            ));
        }
        for data in visible {
            let address = data.address;
            let selected = self.selected_data == Some(address);
            let mut row = div()
                .w_full()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(rgb(if selected { ACCENT } else { BORDER }))
                .bg(rgb(if selected { SELECTED } else { CARD }))
                .cursor_pointer()
                .hover(|style| style.bg(rgb(if selected { SELECTED } else { HOVER })))
                .id(("data", address))
                .on_click(cx.listener(move |workspace, _, _, cx| {
                    workspace.active_view = WorkspaceView::Data;
                    workspace.selected_data = Some(address);
                    workspace.selected_address = None;
                    workspace.selected_reference = None;
                    workspace.status = format!("Selected data 0x{address:x}");
                    cx.notify();
                }))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .child(
                            div()
                                .text_sm()
                                .text_color(rgb(ACCENT))
                                .truncate()
                                .child(data.name.clone()),
                        )
                        .child(div().flex_1())
                        .child(
                            div()
                                .text_xs()
                                .font_family("Cascadia Code")
                                .text_color(rgb(MUTED))
                                .child(format!("0x{:x}", address)),
                        ),
                )
                .child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(rgb(PURPLE))
                        .truncate()
                        .child(data.type_name.clone()),
                )
                .child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(rgb(SUBTLE))
                        .child(format!(
                            "{} bytes  ·  {}% confidence  ·  gen {}",
                            data.size, data.confidence, data.generation
                        )),
                );
            if let Some(comment) = &data.comment {
                row = row.child(
                    div()
                        .mt_2()
                        .text_xs()
                        .text_color(rgb(MUTED))
                        .line_clamp(2)
                        .child(comment.clone()),
                );
            }
            list = list.child(row);
        }
        list
    }

    fn references_list(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let visible: Vec<_> = self
            .references
            .iter()
            .filter(|item| self.reference_matches(item))
            .collect();
        let mut list = self.list_shell("Cross-references", visible.len());
        if visible.is_empty() {
            return list.child(self.empty_state(
                "No matching references",
                "Calls, jumps, reads, and writes will appear here.",
            ));
        }
        for reference in visible {
            let id = reference.id;
            let selected = self.selected_reference == Some(id);
            list = list.child(
                div()
                    .w_full()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(if selected { ACCENT } else { BORDER }))
                    .bg(rgb(if selected { SELECTED } else { CARD }))
                    .cursor_pointer()
                    .hover(|style| style.bg(rgb(if selected { SELECTED } else { HOVER })))
                    .id(("reference", id))
                    .on_click(cx.listener(move |workspace, _, _, cx| {
                        workspace.active_view = WorkspaceView::References;
                        workspace.selected_reference = Some(id);
                        workspace.selected_address = None;
                        workspace.selected_data = None;
                        workspace.status = format!("Selected reference #{id}");
                        cx.notify();
                    }))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(reference_kind_glyph(&reference.kind))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(ACCENT))
                                    .font_family("Cascadia Code")
                                    .child(format!("0x{:x}", reference.from)),
                            )
                            .child(div().text_color(rgb(SUBTLE)).child("→"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(ACCENT))
                                    .font_family("Cascadia Code")
                                    .child(format!("0x{:x}", reference.to)),
                            ),
                    )
                    .child(
                        div()
                            .mt_2()
                            .flex()
                            .items_center()
                            .gap_2()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(reference.kind.clone())
                            .child("·")
                            .child(format!("{}% confidence", reference.confidence))
                            .child(div().flex_1())
                            .child(format!("gen {}", reference.generation)),
                    ),
            );
        }
        list
    }

    fn segments_list(&self) -> impl IntoElement {
        let mut list = self.list_shell("Memory segments", self.segments.len());
        if self.segments.is_empty() {
            return list.child(
                self.empty_state("No segments", "The loader did not expose mapped segments."),
            );
        }
        for segment in &self.segments {
            list = list.child(
                div()
                    .w_full()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(CARD))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(ACCENT))
                                    .truncate()
                                    .child(segment.name.clone()),
                            )
                            .child(div().flex_1())
                            .child(
                                div()
                                    .text_xs()
                                    .font_family("Cascadia Code")
                                    .text_color(rgb(MUTED))
                                    .child(format!("0x{:x}", segment.address)),
                            ),
                    )
                    .child(div().mt_2().text_xs().text_color(rgb(MUTED)).child(format!(
                        "size 0x{:x}  ·  file +0x{:x}  ·  {}",
                        segment.size, segment.file_offset, segment.permissions
                    ))),
            );
        }
        list
    }

    fn symbols_list(&self) -> impl IntoElement {
        let mut list = self.list_shell("Symbols", self.symbols.len());
        for symbol in &self.symbols {
            if !self.query_matches(&format!("{} 0x{:x}", symbol.name, symbol.address)) {
                continue;
            }
            list = list.child(
                div()
                    .w_full()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(CARD))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(ACCENT))
                                    .truncate()
                                    .child(symbol.name.clone()),
                            )
                            .child(div().flex_1())
                            .child(
                                div()
                                    .text_xs()
                                    .font_family("Cascadia Code")
                                    .text_color(rgb(MUTED))
                                    .child(format!("0x{:x}", symbol.address)),
                            ),
                    )
                    .child(div().mt_2().text_xs().text_color(rgb(MUTED)).child(format!(
                        "{} bytes  ·  section {}",
                        symbol.size, symbol.section
                    ))),
            );
        }
        list
    }

    fn assertions_list(&self) -> impl IntoElement {
        let visible: Vec<_> = self
            .assertions
            .iter()
            .filter(|item| {
                self.query_matches(&format!("{} {} {}", item.kind, item.value, item.address))
            })
            .collect();
        let mut list = self.list_shell("Assertions", visible.len());
        if visible.is_empty() {
            return list.child(self.empty_state(
                "No assertions",
                "Human and machine evidence will be listed here.",
            ));
        }
        for assertion in visible {
            list = list.child(
                div()
                    .w_full()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(CARD))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(PURPLE))
                                    .child(assertion.kind.clone()),
                            )
                            .child(div().flex_1())
                            .child(
                                div()
                                    .text_xs()
                                    .font_family("Cascadia Code")
                                    .text_color(rgb(MUTED))
                                    .child(format!("0x{:x}", assertion.address)),
                            ),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_xs()
                            .text_color(rgb(TEXT))
                            .line_clamp(2)
                            .child(assertion.value.clone()),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .line_clamp(2)
                            .child(assertion.note.clone()),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_xs()
                            .text_color(rgb(if assertion.authority == "Human" {
                                AMBER
                            } else {
                                GREEN
                            }))
                            .child(assertion.authority.clone()),
                    ),
            );
        }
        list
    }

    fn empty_state(&self, title: &str, body: &str) -> impl IntoElement {
        div()
            .mt_4()
            .p_4()
            .rounded_md()
            .border_1()
            .border_color(rgb(BORDER))
            .bg(rgb(SURFACE))
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(TEXT))
                    .child(title.to_string()),
            )
            .child(
                div()
                    .mt_2()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .line_clamp(3)
                    .child(body.to_string()),
            )
    }

    fn detail_tabs(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut tabs = div()
            .flex()
            .items_center()
            .gap_1()
            .border_color(rgb(BORDER))
            .border_1();
        for tab in [
            DetailTab::Decompile,
            DetailTab::Assembly,
            DetailTab::Graph,
            DetailTab::Facts,
            DetailTab::Xrefs,
        ] {
            let active = self.detail_tab == tab;
            tabs = tabs.child(
                div()
                    .id(("detail-tab", tab as u64))
                    .px_3()
                    .py_2()
                    .text_xs()
                    .cursor_pointer()
                    .text_color(rgb(if active { TEXT } else { MUTED }))
                    .bg(rgb(if active { SELECTED } else { SURFACE }))
                    .hover(|style| style.bg(rgb(if active { SELECTED } else { HOVER })))
                    .on_click(cx.listener(move |workspace, _, _, cx| {
                        workspace.detail_tab = tab;
                        cx.notify();
                    }))
                    .child(tab.label()),
            );
        }
        tabs
    }

    fn details(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut panel = div()
            .id("details-panel")
            .flex_1()
            .h_full()
            .flex()
            .flex_col()
            .overflow_y_scroll()
            .bg(rgb(SURFACE))
            .text_color(rgb(TEXT));
        panel = panel.child(self.detail_header(cx));
        match self.active_view {
            WorkspaceView::Functions => {
                if let Some(function) = self.selected_function() {
                    panel = panel
                        .child(self.detail_tabs(cx))
                        .child(self.function_detail(function));
                } else {
                    panel = panel.child(self.empty_state("Select a function", "Choose a function from the symbol navigator to inspect pseudocode, facts, and references."));
                }
            }
            WorkspaceView::Data => panel = panel.child(self.data_detail()),
            WorkspaceView::References => panel = panel.child(self.reference_detail()),
            WorkspaceView::Segments => panel = panel.child(self.image_detail()),
            WorkspaceView::Symbols => panel = panel.child(self.symbol_detail()),
            WorkspaceView::Assertions => panel = panel.child(self.assertion_detail()),
        }
        panel
    }

    fn detail_header(&self, _cx: &mut Context<Self>) -> impl IntoElement {
        let title = match self.active_view {
            WorkspaceView::Functions => self
                .selected_function()
                .map(|f| f.name.clone())
                .unwrap_or_else(|| "Function explorer".into()),
            WorkspaceView::Data => self
                .selected_data_row()
                .map(|d| d.name.clone())
                .unwrap_or_else(|| "Data explorer".into()),
            WorkspaceView::References => self
                .selected_reference_row()
                .map(|r| format!("Reference #{}", r.id))
                .unwrap_or_else(|| "Cross-reference explorer".into()),
            WorkspaceView::Segments => "Memory map".into(),
            WorkspaceView::Symbols => "Symbol table".into(),
            WorkspaceView::Assertions => "Evidence ledger".into(),
        };
        div()
            .w_full()
            .p_5()
            .pb_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .text_xl()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child(title),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .px_2()
                            .py_1()
                            .rounded_sm()
                            .bg(rgb(RAISED))
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child("read-only workspace"),
                    ),
            )
            .child(div().mt_2().text_xs().text_color(rgb(MUTED)).child(format!(
                "{}  ·  base {}  ·  entry {}",
                self.project_path.display(),
                format_address(self.base),
                format_address(self.entry)
            )))
    }

    fn function_detail(&self, function: &FunctionRow) -> impl IntoElement {
        let references_in: Vec<_> = self
            .references
            .iter()
            .filter(|r| r.to == function.address)
            .collect();
        let references_out: Vec<_> = self
            .references
            .iter()
            .filter(|r| r.from == function.address)
            .collect();
        let main = match self.detail_tab {
            DetailTab::Decompile => self.reconstruction_view(function).into_any_element(),
            DetailTab::Assembly => self.assembly_view(function).into_any_element(),
            DetailTab::Graph => self.graph_view(function).into_any_element(),
            DetailTab::Facts => self.function_facts(function).into_any_element(),
            DetailTab::Xrefs => self
                .xrefs_view(function.address, &references_in, &references_out)
                .into_any_element(),
        };
        div()
            .flex()
            .flex_1()
            .w_full()
            .gap_3()
            .p_5()
            .pt_3()
            .child(div().flex_1().min_w(px(420.0)).child(main))
            .child(self.function_rail(function, references_in.len(), references_out.len()))
    }

    fn reconstruction_view(&self, function: &FunctionRow) -> impl IntoElement {
        let provenance = function.provenance.as_deref().unwrap_or("not recorded");
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.empty_state(
                "C source is not persisted",
                "This capsule records discovered facts and provenance, not reconstructed source text. Re-open the original image with a native analysis session to produce a source view.",
            ))
            .child(self.metric_card("DISCOVERY PROVENANCE", provenance.to_string(), ACCENT))
            .child(self.fact_row("Function", &function.name))
    }

    fn function_rail(
        &self,
        function: &FunctionRow,
        incoming: usize,
        outgoing: usize,
    ) -> impl IntoElement {
        div()
            .w(px(250.0))
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.metric_card("ADDRESS", format!("0x{:x}", function.address), ACCENT))
            .child(self.metric_card("SIZE", format!("0x{:x} bytes", function.size), PURPLE))
            .child(self.metric_card(
                "CONFIDENCE",
                format!("{}%", function.confidence),
                confidence_color(function.confidence),
            ))
            .child(self.metric_card(
                "XREFS",
                format!("{} in  ·  {} out", incoming, outgoing),
                GREEN,
            ))
            .child(
                self.metric_card(
                    "PROVENANCE",
                    function
                        .provenance
                        .clone()
                        .unwrap_or_else(|| "not recorded".into()),
                    ACCENT,
                ),
            )
    }

    fn metric_card(&self, label: &str, value: String, color: u32) -> impl IntoElement {
        div()
            .p_3()
            .rounded_md()
            .border_1()
            .border_color(rgb(BORDER))
            .bg(rgb(RAISED))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(SUBTLE))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .mt_1()
                    .text_sm()
                    .font_family("Cascadia Code")
                    .text_color(rgb(color))
                    .child(value),
            )
    }

    fn assembly_view(&self, function: &FunctionRow) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .p_4()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(AMBER))
                    .bg(rgb(RAISED))
                    .child(div().text_sm().text_color(rgb(AMBER)).child("Native bytes are not in this project capsule"))
                    .child(div().mt_2().text_xs().text_color(rgb(MUTED)).line_clamp(4).child("Ventris will not invent an assembly listing. Re-open the original image with a native-byte-backed analysis session to enable instruction rows; the persisted facts below remain safe to inspect.")),
            )
            .child(
                div()
                    .p_4()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(CODE_BG))
                    .font_family("Cascadia Code")
                    .text_sm()
                    .child(format!("; function {}\n; address 0x{:x}\n; extent 0x{:x} bytes\n; target {}", function.name, function.address, function.size, self.target)),
            )
    }

    fn graph_view(&self, function: &FunctionRow) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.empty_state(
                "Control-flow graph unavailable",
                "This capsule does not persist decoded instructions, basic blocks, or CFG edges. Use Xrefs for the persisted function-level relations.",
            ))
            .child(self.fact_row("Function", &function.name))
            .child(self.fact_row("Address", &format!("0x{:x}", function.address)))
    }

    fn function_facts(&self, function: &FunctionRow) -> impl IntoElement {
        let mut facts = div().flex().flex_col().gap_2();
        facts = facts
            .child(self.fact_row("Name", &function.name))
            .child(self.fact_row(
                "Signature",
                function.signature.as_deref().unwrap_or("not persisted"),
            ))
            .child(self.fact_row("Address", &format!("0x{:x}", function.address)))
            .child(self.fact_row("Size", &format!("{} bytes", function.size)))
            .child(self.fact_row("Generation", &function.generation.to_string()));
        if let Some(comment) = &function.comment {
            facts = facts.child(self.fact_row("Comment", comment));
        }
        facts.child(
            div()
                .mt_2()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(rgb(BORDER))
                .bg(rgb(RAISED))
                .child(div().text_xs().text_color(rgb(SUBTLE)).child("EDITING CONTRACT"))
                .child(div().mt_2().text_xs().text_color(rgb(MUTED)).child("Rename and comment actions will append human assertions instead of overwriting machine evidence.")),
        )
    }

    fn xrefs_view<'a>(
        &self,
        address: u64,
        incoming: &[&'a ReferenceRow],
        outgoing: &[&'a ReferenceRow],
    ) -> impl IntoElement {
        let mut view = div().flex().flex_col().gap_3();
        view = view
            .child(self.xref_group("INCOMING", incoming, address))
            .child(self.xref_group("OUTGOING", outgoing, address));
        view
    }

    fn xref_group<'a>(
        &self,
        title: &str,
        rows: &[&'a ReferenceRow],
        _address: u64,
    ) -> impl IntoElement {
        let mut group = div()
            .p_3()
            .rounded_md()
            .border_1()
            .border_color(rgb(BORDER))
            .bg(rgb(RAISED))
            .child(div().text_xs().text_color(rgb(SUBTLE)).child(format!(
                "{}  ·  {}",
                title,
                rows.len()
            )));
        if rows.is_empty() {
            return group.child(
                div()
                    .mt_2()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child("No persisted references."),
            );
        }
        for reference in rows {
            group = group.child(
                div()
                    .mt_2()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_xs()
                    .font_family("Cascadia Code")
                    .child(format!("0x{:x} → 0x{:x}", reference.from, reference.to))
                    .child(div().flex_1())
                    .child(
                        div()
                            .font_family(".SystemUIFont")
                            .text_color(rgb(MUTED))
                            .child(reference.kind.clone()),
                    ),
            );
        }
        group
    }

    fn data_detail(&self) -> impl IntoElement {
        let Some(data) = self.selected_data_row() else {
            return self
                .empty_state(
                    "Select data",
                    "Choose a recovered global or field from the navigator.",
                )
                .into_any_element();
        };
        let provenance = data
            .provenance
            .clone()
            .unwrap_or_else(|| "not recorded".into());
        let mut detail = div()
            .flex()
            .flex_1()
            .gap_3()
            .p_5()
            .pt_3()
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(self.empty_state(
                        "Declaration source is not persisted",
                        "This capsule stores recovered data facts and discovery provenance, not declaration text.",
                    ))
                    .child(self.metric_card("DISCOVERY PROVENANCE", provenance, ACCENT))
                    .child(self.fact_row("Name", &data.name))
                    .child(self.fact_row("Type", &data.type_name)),
            )
            .child(
                div()
                    .w(px(250.0))
                    .flex_shrink_0()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(self.metric_card("ADDRESS", format!("0x{:x}", data.address), ACCENT))
                    .child(self.metric_card("TYPE", data.type_name.clone(), PURPLE))
                    .child(self.metric_card("SIZE", format!("{} bytes", data.size), GREEN))
                    .child(self.metric_card("CONFIDENCE", format!("{}%", data.confidence), confidence_color(data.confidence))),
            );
        if let Some(comment) = &data.comment {
            detail = detail.child(self.fact_row("Comment", comment));
        }
        detail.into_any_element()
    }
    fn reference_detail(&self) -> impl IntoElement {
        let Some(reference) = self.selected_reference_row() else {
            return self
                .empty_state(
                    "Select a reference",
                    "Choose an xref to inspect its endpoints and evidence.",
                )
                .into_any_element();
        };
        let from = self.address_label(reference.from);
        let to = self.address_label(reference.to);
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_5()
            .pt_3()
            .child(self.fact_row("Kind", &reference.kind))
            .child(self.fact_row("From", &format!("{}  (0x{:x})", from, reference.from)))
            .child(self.fact_row("To", &format!("{}  (0x{:x})", to, reference.to)))
            .child(self.fact_row("Confidence", &format!("{}%", reference.confidence)))
            .child(self.fact_row("Generation", &reference.generation.to_string()))
            .child(
                self.fact_row(
                    "Offset",
                    &reference
                        .offset
                        .map(|v| format!("{v:+#x}"))
                        .unwrap_or_else(|| "none".into()),
                ),
            )
            .into_any_element()
    }

    fn image_detail(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_5()
            .pt_3()
            .child(self.metric_card("FILE SIZE", format_bytes(self.file_size), ACCENT))
            .child(self.metric_card("BASE", format_address(self.base), PURPLE))
            .child(self.metric_card("ENTRY", format_address(self.entry), GREEN))
            .child(
                div()
                    .p_4()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(RAISED))
                    .child(div().text_sm().child("Memory facts"))
                    .child(div().mt_2().text_xs().text_color(rgb(MUTED)).child(format!(
                        "{} segments, {} symbols, {} relocations are persisted in the image model.",
                        self.segments.len(),
                        self.symbols.len(),
                        self.references.len()
                    ))),
            )
    }

    fn symbol_detail(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_5()
            .pt_3()
            .child(self.empty_state("Symbol context", "Select a symbol to focus this pane. Symbol rows currently expose their persisted address, size, and section."))
    }

    fn assertion_detail(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_5()
            .pt_3()
            .child(
                div()
                    .p_4()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(RAISED))
                    .child(div().text_sm().child("Evidence ledger"))
                    .child(div().mt_2().text_xs().text_color(rgb(MUTED)).child("Assertions are deliberately visible beside inferred facts. Human assertions are never silently replaced by a new analysis generation.")),
            )
    }

    fn fact_row(&self, label: &str, value: &str) -> impl IntoElement {
        div()
            .p_3()
            .rounded_md()
            .border_1()
            .border_color(rgb(BORDER))
            .bg(rgb(RAISED))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(SUBTLE))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .mt_1()
                    .text_sm()
                    .text_color(rgb(TEXT))
                    .line_clamp(4)
                    .child(value.to_string()),
            )
    }

    fn address_label(&self, address: u64) -> String {
        self.functions
            .iter()
            .find(|function| function.address == address)
            .map(|function| function.name.clone())
            .or_else(|| {
                self.data
                    .iter()
                    .find(|data| data.address == address)
                    .map(|data| data.name.clone())
            })
            .or_else(|| {
                self.symbols
                    .iter()
                    .find(|symbol| symbol.address == address)
                    .map(|symbol| symbol.name.clone())
            })
            .unwrap_or_else(|| format!("0x{address:x}"))
    }

    fn handle_key(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        let key = event.keystroke.key.to_ascii_lowercase();
        match key.as_str() {
            "escape" => {
                self.query.clear();
                self.search_focused = false;
            }
            "/" if !self.search_focused => self.search_focused = true,
            "backspace" if self.search_focused => {
                self.query.pop();
            }
            "enter" if self.search_focused => {
                self.select_first_match();
                self.search_focused = false;
            }
            "arrowup" | "up" => self.move_selection(-1),
            "arrowdown" | "down" => self.move_selection(1),
            "f1" => self.active_view = WorkspaceView::Functions,
            "f2" => self.active_view = WorkspaceView::Data,
            "f3" => self.active_view = WorkspaceView::References,
            "f4" => self.active_view = WorkspaceView::Segments,
            _ => {
                if self.search_focused {
                    let character = event.keystroke.key_char.clone().or_else(|| {
                        if key.chars().count() == 1 {
                            Some(key.clone())
                        } else {
                            None
                        }
                    });
                    if let Some(character) =
                        character.filter(|value| !value.chars().all(char::is_control))
                    {
                        self.query.push_str(&character);
                    }
                }
            }
        }
        self.status = if self.search_focused {
            format!(
                "Search active · {} result(s)",
                self.count_for(self.active_view)
            )
        } else {
            format!(
                "{} · {} result(s)",
                self.active_view.label(),
                self.count_for(self.active_view)
            )
        };
        cx.notify();
    }

    fn select_first_match(&mut self) {
        match self.active_view {
            WorkspaceView::Functions => {
                self.selected_address = self
                    .functions
                    .iter()
                    .find(|f| self.function_matches(f))
                    .map(|f| f.address)
            }
            WorkspaceView::Data => {
                self.selected_data = self
                    .data
                    .iter()
                    .find(|d| self.data_matches(d))
                    .map(|d| d.address)
            }
            WorkspaceView::References => {
                self.selected_reference = self
                    .references
                    .iter()
                    .find(|r| self.reference_matches(r))
                    .map(|r| r.id)
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: isize) {
        match self.active_view {
            WorkspaceView::Functions => {
                let visible: Vec<u64> = self
                    .functions
                    .iter()
                    .filter(|f| self.function_matches(f))
                    .map(|f| f.address)
                    .collect();
                if let Some(next) = next_index(
                    visible
                        .iter()
                        .position(|address| Some(*address) == self.selected_address),
                    visible.len(),
                    delta,
                ) {
                    self.selected_address = visible.get(next).copied();
                }
            }
            WorkspaceView::Data => {
                let visible: Vec<u64> = self
                    .data
                    .iter()
                    .filter(|d| self.data_matches(d))
                    .map(|d| d.address)
                    .collect();
                if let Some(next) = next_index(
                    visible
                        .iter()
                        .position(|address| Some(*address) == self.selected_data),
                    visible.len(),
                    delta,
                ) {
                    self.selected_data = visible.get(next).copied();
                }
            }
            WorkspaceView::References => {
                let visible: Vec<usize> = self
                    .references
                    .iter()
                    .filter(|r| self.reference_matches(r))
                    .map(|r| r.id)
                    .collect();
                if let Some(next) = next_index(
                    visible
                        .iter()
                        .position(|id| Some(*id) == self.selected_reference),
                    visible.len(),
                    delta,
                ) {
                    self.selected_reference = visible.get(next).copied();
                }
            }
            _ => {}
        }
    }
}

impl Render for ProjectWorkspace {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = match self.active_view {
            WorkspaceView::Functions => self.function_list(cx).into_any_element(),
            WorkspaceView::Data => self.data_list(cx).into_any_element(),
            WorkspaceView::References => self.references_list(cx).into_any_element(),
            WorkspaceView::Segments => self.segments_list().into_any_element(),
            WorkspaceView::Symbols => self.symbols_list().into_any_element(),
            WorkspaceView::Assertions => self.assertions_list().into_any_element(),
        };
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(BG))
            .on_key_down(cx.listener(|workspace, event, _, cx| workspace.handle_key(event, cx)))
            .child(self.top_bar(cx))
            .child(
                div()
                    .flex_1()
                    .flex()
                    .child(self.sidebar(cx))
                    .child(content)
                    .child(self.details(cx)),
            )
    }
}

impl FunctionRow {
    fn from_project(function: &ProjectFunction) -> Self {
        Self {
            address: function.address,
            name: function
                .name
                .clone()
                .unwrap_or_else(|| format!("sub_{:x}", function.address)),
            size: function.size,
            signature: function.signature.clone(),
            comment: function.comment.clone(),
            provenance: function.source.clone(),
            confidence: function.confidence,
            generation: function.generation,
        }
    }
}

impl DataRow {
    fn from_project(data: &ProjectData) -> Self {
        Self {
            address: data.address,
            name: data
                .name
                .clone()
                .unwrap_or_else(|| format!("data_{:x}", data.address)),
            size: data.size,
            type_name: data.type_name.clone().unwrap_or_else(|| "unknown".into()),
            comment: data.comment.clone(),
            provenance: data.source.clone(),
            confidence: data.confidence,
            generation: data.generation,
        }
    }
}

impl ReferenceRow {
    fn from_project(id: usize, reference: &ProjectReference) -> Self {
        Self {
            id,
            from: reference.from,
            to: reference.to,
            kind: match reference.kind {
                ProjectReferenceKind::Call => "call",
                ProjectReferenceKind::Jump => "jump",
                ProjectReferenceKind::Read => "read",
                ProjectReferenceKind::Write => "write",
                ProjectReferenceKind::String => "string",
                ProjectReferenceKind::FunctionPointer => "function-pointer",
                ProjectReferenceKind::Field => "field",
            }
            .into(),
            offset: reference.offset,
            confidence: reference.confidence,
            generation: reference.generation,
        }
    }
}

impl SegmentRow {
    fn from_project(segment: &ProjectSegment) -> Self {
        let mut permissions = String::new();
        permissions.push(if segment.read == Some(true) { 'r' } else { '-' });
        permissions.push(if segment.write == Some(true) {
            'w'
        } else {
            '-'
        });
        permissions.push(if segment.execute == Some(true) {
            'x'
        } else {
            '-'
        });
        Self {
            name: segment.name.clone().unwrap_or_else(|| "unnamed".into()),
            address: segment.address,
            size: segment.size,
            file_offset: segment.file_offset,
            file_size: segment.file_size,
            permissions,
        }
    }
}

impl SymbolRow {
    fn from_project(symbol: &ProjectSymbol) -> Self {
        Self {
            address: symbol.address,
            name: symbol.name.clone(),
            size: symbol.size,
            section: symbol.section,
        }
    }
}

impl AssertionRow {
    fn from_project(assertion: &ProjectAssertion) -> Self {
        Self {
            address: assertion.address,
            kind: assertion.kind.clone(),
            value: assertion.value.clone(),
            note: assertion.note.clone(),
            authority: format!("{:?}", assertion.authority),
        }
    }
}

fn next_index(current: Option<usize>, length: usize, delta: isize) -> Option<usize> {
    if length == 0 {
        return None;
    }
    let Some(current) = current else {
        return Some(if delta < 0 { length - 1 } else { 0 });
    };
    Some((current as isize + delta).clamp(0, length as isize - 1) as usize)
}

fn confidence_color(confidence: u8) -> u32 {
    match confidence {
        0..=39 => RED,
        40..=79 => AMBER,
        _ => GREEN,
    }
}

fn reference_kind_glyph(kind: &str) -> impl IntoElement {
    let (glyph, color) = match kind {
        "call" => ("ƒ", GREEN),
        "jump" => ("↪", PURPLE),
        "read" => ("R", ACCENT),
        "write" => ("W", AMBER),
        _ => ("·", MUTED),
    };
    div()
        .w(px(18.0))
        .text_center()
        .text_color(rgb(color))
        .child(glyph)
}

fn format_address(address: Option<u64>) -> String {
    address
        .map(|value| format!("0x{value:x}"))
        .unwrap_or_else(|| "—".into())
}

fn format_bytes(size: u64) -> String {
    if size >= 1024 * 1024 {
        format!("{:.1} MiB", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.1} KiB", size as f64 / 1024.0)
    } else {
        format!("{} B", size)
    }
}

fn main() {
    let project_path = env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: ventris-gpui <project.vproj>");
        std::process::exit(2);
    });
    let project = Project::load_from(&project_path).unwrap_or_else(|error| {
        eprintln!("{}: {error}", project_path.display());
        std::process::exit(2);
    });
    let workspace = ProjectWorkspace::from_project(project_path, project);

    Application::new().run(move |cx: &mut App| {
        gpui_component::init(cx);
        let bounds = Bounds::centered(None, size(px(1600.0), px(960.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |_, cx| cx.new(|_| workspace),
        )
        .expect("open Ventris GPUI window");
        cx.activate(true);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_db::{Project, ProjectFunction, ProjectImage};

    #[test]
    fn project_workspace_keeps_navigation_and_function_facts() {
        let mut project = Project::new(ProjectImage {
            source: "fixture.elf".into(),
            loader: "elf".into(),
            target: Some("ps2".into()),
            content_hash: 0x1234,
            ..ProjectImage::default()
        });
        project.functions.push(ProjectFunction {
            address: 0x1000,
            size: 0x40,
            name: Some("main".into()),
            signature: Some("int main(void)".into()),
            confidence: 95,
            generation: 2,
            ..ProjectFunction::default()
        });
        let workspace = ProjectWorkspace::from_project("sample.vproj".into(), project);
        assert_eq!(workspace.functions.len(), 1);
        assert_eq!(workspace.functions[0].name, "main");
        assert_eq!(workspace.functions[0].generation, 2);
        assert_eq!(workspace.selected_address, Some(0x1000));
        assert_eq!(workspace.active_view, WorkspaceView::Functions);
        assert_eq!(workspace.target, "ps2");
        assert_eq!(workspace.image_hash, 0x1234);
    }

    #[test]
    fn search_and_selection_follow_function_name_and_address() {
        let mut project = Project::new(ProjectImage::default());
        project.functions.extend([
            ProjectFunction {
                address: 0x1000,
                name: Some("main".into()),
                ..ProjectFunction::default()
            },
            ProjectFunction {
                address: 0x2000,
                name: Some("render_frame".into()),
                ..ProjectFunction::default()
            },
        ]);
        let mut workspace = ProjectWorkspace::from_project("sample.vproj".into(), project);
        workspace.query = "render".into();
        workspace.selected_address = None;
        workspace.select_first_match();
        assert_eq!(workspace.selected_address, Some(0x2000));
        assert_eq!(workspace.count_for(WorkspaceView::Functions), 1);
        workspace.query = "0x1000".into();
        assert_eq!(workspace.count_for(WorkspaceView::Functions), 1);
    }

    #[test]
    fn keyboard_navigation_clamps_and_cycles_without_panicking() {
        assert_eq!(next_index(None, 3, 1), Some(0));
        assert_eq!(next_index(Some(0), 3, -1), Some(0));
        assert_eq!(next_index(Some(2), 3, 1), Some(2));
        assert_eq!(next_index(None, 0, 1), None);
    }
}
